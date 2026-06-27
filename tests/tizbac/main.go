package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"sync/atomic"

	"local.ly/gopbs/pbscommon"

	"github.com/cornelk/hashmap"
)

var didxMagic = []byte{28, 145, 78, 165, 25, 186, 179, 205}

type ChunkState struct {
	assignments        []string
	assignments_offset []uint64
	pos                uint64
	wrid               uint64
	chunkcount         uint64
	chunkdigests       hash.Hash
	current_chunk      []byte
	C                  pbscommon.Chunker
	newchunk           *atomic.Uint64
	reusechunk         *atomic.Uint64
	knownChunks        *hashmap.Map[string, bool]
}

type DidxEntry struct {
	offset uint64
	digest []byte
}

func (c *ChunkState) Init(newchunk *atomic.Uint64, reusechunk *atomic.Uint64, knownChunks *hashmap.Map[string, bool]) {
	c.assignments = make([]string, 0)
	c.assignments_offset = make([]uint64, 0)
	c.pos = 0
	c.chunkcount = 0
	c.chunkdigests = sha256.New()
	c.current_chunk = make([]byte, 0)
	c.C = pbscommon.Chunker{}
	c.C.New(1024 * 1024 * 4)
	c.reusechunk = reusechunk
	c.newchunk = newchunk
	c.knownChunks = knownChunks
}

func (c *ChunkState) HandleData(b []byte, client *pbscommon.PBSClient) {
	chunkpos := c.C.Scan(b)

	if chunkpos == 0 {
		//No break happened, just append data
		c.current_chunk = append(c.current_chunk, b...)
	} else {

		for chunkpos > 0 {
			//Append data until break position
			c.current_chunk = append(c.current_chunk, b[:chunkpos]...)

			h := sha256.New()
			// TODO: error handling inside callback
			h.Write(c.current_chunk)
			bindigest := h.Sum(nil)
			shahash := hex.EncodeToString(bindigest)

			if _, ok := c.knownChunks.GetOrInsert(shahash, true); !ok {
				fmt.Printf("New chunk[%s] %d bytes\n", shahash, len(c.current_chunk))
				c.newchunk.Add(1)

				client.UploadDynamicCompressedChunk(c.wrid, shahash, c.current_chunk)
			} else {
				fmt.Printf("Reuse chunk[%s] %d bytes\n", shahash, len(c.current_chunk))
				c.reusechunk.Add(1)
			}

			// TODO: error handling inside callback
			binary.Write(c.chunkdigests, binary.LittleEndian, (c.pos + uint64(len(c.current_chunk))))
			// TODO: error handling inside callback
			c.chunkdigests.Write(h.Sum(nil))

			c.assignments_offset = append(c.assignments_offset, c.pos)
			c.assignments = append(c.assignments, shahash)
			c.pos += uint64(len(c.current_chunk))
			c.chunkcount += 1

			c.current_chunk = make([]byte, 0)
			b = b[chunkpos:] //Take remainder of data
			chunkpos = c.C.Scan(b)

		}

		//No further break happened, append remaining data
		c.current_chunk = append(c.current_chunk, b...)
	}
}

func (c *ChunkState) Eof(client *pbscommon.PBSClient) {
	//Here we write the remainder of data for which cyclic hash did not trigger

	if len(c.current_chunk) > 0 {
		h := sha256.New()
		_, err := h.Write(c.current_chunk)
		if err != nil {
			panic(err)
		}

		shahash := hex.EncodeToString(h.Sum(nil))
		binary.Write(c.chunkdigests, binary.LittleEndian, (c.pos + uint64(len(c.current_chunk))))
		c.chunkdigests.Write(h.Sum(nil))

		if _, ok := c.knownChunks.GetOrInsert(shahash, true); !ok {
			fmt.Printf("New chunk[%s] %d bytes\n", shahash, len(c.current_chunk))
			client.UploadDynamicCompressedChunk(c.wrid, shahash, c.current_chunk)
			c.newchunk.Add(1)
		} else {
			fmt.Printf("Reuse chunk[%s] %d bytes\n", shahash, len(c.current_chunk))
			c.reusechunk.Add(1)
		}
		c.assignments_offset = append(c.assignments_offset, c.pos)
		c.assignments = append(c.assignments, shahash)
		c.pos += uint64(len(c.current_chunk))
		c.chunkcount += 1

	}
	//Avoid incurring in request entity too large by chunking assignment PUT requests in blocks of at most 128 chunks
	for k := 0; k < len(c.assignments); k += 128 {
		k2 := k + 128
		if k2 > len(c.assignments) {
			k2 = len(c.assignments)
		}
		client.AssignDynamicChunks(c.wrid, c.assignments[k:k2], c.assignments_offset[k:k2])
	}

	client.CloseDynamicIndex(c.wrid, hex.EncodeToString(c.chunkdigests.Sum(nil)), c.pos, c.chunkcount)
}

func main() {
	err := pxar_only("/pxar/tizbac.pxar", "/source")
	if err != nil {
		fmt.Fprintf(os.Stderr, "pxar_only failed: %v\n", err)
		os.Exit(1)
	}

}

func backup_stream(client *pbscommon.PBSClient, newchunk, reusechunk *atomic.Uint64, filename string, stream io.Reader) error {
	knownChunks := hashmap.New[string, bool]()
	client.Connect(false, "host")
	previousDidx, err := client.DownloadPreviousToBytes(filename)
	if err != nil {
		return err
	}

	fmt.Printf("Downloaded previous DIDX: %d bytes\n", len(previousDidx))

	if !bytes.HasPrefix(previousDidx, didxMagic) {
		fmt.Printf("Previous index has wrong magic (%s)!\n", previousDidx[:8])

	} else {
		//Header as per proxmox documentation is fixed size of 4096 bytes,
		//then offset of type uint64 and sha256 digests follow , so 40 byte each record until EOF
		previousDidx = previousDidx[4096:]
		for i := 0; i*40 < len(previousDidx); i += 1 {
			e := DidxEntry{}
			e.offset = binary.LittleEndian.Uint64(previousDidx[i*40 : i*40+8])
			e.digest = previousDidx[i*40+8 : i*40+40]
			shahash := hex.EncodeToString(e.digest)
			fmt.Printf("Previous: %s\n", shahash)
			knownChunks.Set(shahash, true)
		}
	}

	fmt.Printf("Known chunks: %d!\n", knownChunks.Len())

	streamChunk := ChunkState{}
	streamChunk.Init(newchunk, reusechunk, knownChunks)

	streamChunk.wrid, err = client.CreateDynamicIndex(filename)
	if err != nil {
		return err
	}
	B := make([]byte, 65536)
	for {

		n, err := stream.Read(B)

		b := B[:n]

		streamChunk.HandleData(b, client)

		if err == io.EOF {
			break
		}
	}

	streamChunk.Eof(client)

	client.CloseDynamicIndex(streamChunk.wrid, hex.EncodeToString(streamChunk.chunkdigests.Sum(nil)), streamChunk.pos, streamChunk.chunkcount)

	err = client.UploadManifest()
	if err != nil {
		return err
	}

	return client.Finish()
}

func pxar_only(pxarOut string, backupdir string) error {
	knownChunks := hashmap.New[string, bool]()
	archive := &pbscommon.PXARArchive{}
	archive.ArchiveName = "tizbac.pxar.didx"

	f, err := os.Create(pxarOut)
	if err != nil {
		return err
	}
	defer f.Close()

	newchunk := &atomic.Uint64{}
	reusechunk := &atomic.Uint64{}

	pxarChunk := ChunkState{}
	pxarChunk.Init(newchunk, reusechunk, knownChunks)

	pcat1Chunk := ChunkState{}
	pcat1Chunk.Init(newchunk, reusechunk, knownChunks)

	// pxarChunk.wrid, err = client.CreateDynamicIndex(archive.ArchiveName)
	// if err != nil {
	// 	return err
	// }
	// pcat1Chunk.wrid, err = client.CreateDynamicIndex("catalog.pcat1.didx")
	// if err != nil {
	// 	return err
	// }

	archive.WriteCB = func(b []byte) {
		f.Write(b)
	}

	// archive.CatalogWriteCB = func(b []byte) {
	// 	pcat1Chunk.HandleData(b, client)
	// }

	archive.WriteDir(backupdir, "", true)

	// pxarChunk.Eof(client)
	// pcat1Chunk.Eof(client)
	//
	return nil
}
