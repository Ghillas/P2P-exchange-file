package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"os"
	"strconv"
)

type peer_connected struct {
	adresse_peer    []string
	public_key_peer peer_key
}

type peer_key struct {
	peer string
	key  []byte
}

type peer_root struct {
	peer string
	root []byte
}

type hello_message struct {
	Id         uint32
	Type       uint8
	Length     uint16
	Extensions uint32
	Name       string
	Signature  []byte
}

type message struct {
	Id        uint32
	Type      uint8
	Length    uint16
	Body      []byte
	Signature []byte
}

type get_datum struct {
	Id        uint32
	Type      uint8
	Length    uint16
	Hash      []byte
	DatumType uint8
	Value     []byte
	Signature []byte
}

type tree struct {
	NbChilds int
	Chunks   []chunk //les enfants qui sont des chuncks
	Trees    []tree  //Les enfants qui sont des bigFile (ou tree)
	COrT     []int   //0 if chunk, 1 if tree, -1 if empty
	Hash     [32]byte
	Data     []byte
}

type chunk struct {
	Hash [32]byte
	Data []byte
}

type directory struct {
	NbChilds    int
	EntryNames  []string
	EntryHashs  [][32]byte
	Chunks      []chunk     //les enfants qui sont des chuncks
	Trees       []tree      //Les enfants qui sont des bigFile (ou tree)
	Directories []directory //Les enfants qui sont des
	COrTOrD     []int       //0 if chunk, 1 if tree, 2 if directory -1 if empty
	Hash        [32]byte
	Data        []byte
}

//functions

func helloToByte(mess hello_message) []byte {
	requete := make([]byte, 11)
	binary.BigEndian.PutUint32(requete[0:4], mess.Id)
	requete[4] = byte(mess.Type)
	binary.BigEndian.PutUint16(requete[5:7], mess.Length)
	binary.BigEndian.PutUint32(requete[7:11], mess.Extensions)
	requete = append(requete, []byte(mess.Name)...)
	signa := calcul_signature(requete)
	requete = append(requete, signa...)

	return requete
}

func messageToByte(mess message) []byte {
	requete := make([]byte, 7)
	binary.BigEndian.PutUint32(requete[:4], mess.Id)
	requete[4] = byte(mess.Type)
	binary.BigEndian.PutUint16(requete[5:7], mess.Length)
	requete = append(requete, []byte(mess.Body)...)
	signa := calcul_signature(requete)
	requete = append(requete, signa...)

	return requete
}

func byteArrayToHelloStruct(myArray []byte) hello_message {
	if len(myArray) < 11 {
		return hello_message{}
	} else {
		taille := binary.BigEndian.Uint16(myArray[5:7])
		overhead := 4
		if taille < 4 {
			overhead = 0
		}
		return hello_message{
			Id:         binary.BigEndian.Uint32(myArray[:4]),
			Type:       uint8(myArray[4]),
			Length:     taille,
			Extensions: binary.BigEndian.Uint32(myArray[7:11]),
			Name:       string(myArray[11 : 11+taille-uint16(overhead)]),
			Signature:  getSignature(myArray[11+taille-uint16(overhead):]),
			//Signature:  *b.SetBytes(myArray[11+taille:]),
			//La signature a une taille de 64 bytes, soit 256 bits
		}
	}
}

func byteArrayToMessageStruct(myArray []byte) message {
	if len(myArray) < 7 {
		return message{}
	} else {
		taille := binary.BigEndian.Uint16(myArray[5:7])
		return message{
			Id:        binary.BigEndian.Uint32(myArray[:4]),
			Type:      uint8(myArray[4]),
			Length:    taille,
			Body:      myArray[7 : 7+taille],
			Signature: getSignature(myArray[7+taille:]),
		}
	}
}

func byteArrayToGetDatumStruct(myArray []byte) get_datum {
	taille := binary.BigEndian.Uint16(myArray[5:7])
	res := get_datum{Id: binary.BigEndian.Uint32(myArray[:4]),
		Type:      uint8(myArray[4]),
		Length:    taille,
		Hash:      myArray[7 : 7+32], // + 32 pour la taille du hash
		DatumType: uint8(3),
	}
	if res.Type == 132 {
		res.DatumType = uint8(myArray[39])
		res.Value = myArray[40 : 40+taille-32-1 /*7+taille+uint16(overhead)*/]
	}
	return res
}

func getDatumToByteArray(getData get_datum) []byte {
	requete := make([]byte, 7)
	binary.BigEndian.PutUint32(requete[:4], getData.Id)
	requete[4] = byte(getData.Type)
	binary.BigEndian.PutUint16(requete[5:7], getData.Length)
	requete = append(requete, getData.Hash...)
	if getData.Type == 132 {
		requete = append(requete, byte(getData.DatumType))
		requete = append(requete, []byte(getData.Value)...)
	}
	return requete
}

/**
 * this function take a byte array of a directory returns it under the form of an array of file names and un array of hashs (array of byte arrays)
 * !!! the byte of datum type must have been deleted from arr !!!
 */
func getDirectory(arr []byte) ([]string, [][]byte) {
	nameArray := make([]string, 0)
	hashArray := make([][]byte, 0)

	nbElements := len(arr) / 64
	for i := 0; i < nbElements; i++ {
		nameArr := arr[i*64 : 32+i*64]
		//We get rid of the padding
		k := 0
		var nameData []byte
		for k < 32 {
			if nameArr[k] == 0 {
				nameData = nameArr[:k]
				break
			}
			k++
		}
		nameArray = append(nameArray, string(nameData))
		hashArray = append(hashArray, make([]byte, 0))
		hashArray[i] = arr[i*64+32 : 64+i*64]
	}

	return nameArray, hashArray
}

func printDir(dir []string) {
	if len(dir) == 0 {
		fmt.Println("This folder is empty...")
	} else {
		for i := 0; i < len(dir); i++ {
			fmt.Println(strconv.Itoa(i) + " - " + dir[i])
		}
	}
}

func printHello(hello hello_message) {
	fmt.Printf("hello => Id : %d, Type : %d, Length : %d, Extensions : %d, Name : %s, Signature : %T\n",
		hello.Id, hello.Type, hello.Length, hello.Extensions, hello.Name, hello.Signature)
}

func printMessage(mess message) {
	if mess.Type == 132 {
		fmt.Printf("message => Id : %d, Type : %d, Length : %d\n",
			mess.Id, mess.Type, mess.Length)
	} else {
		fmt.Printf("message => Id : %d, Type : %d, Length : %d, Body : %s\n",
			mess.Id, mess.Type, mess.Length, mess.Body)
	}
}

/*
func printDatum(mess get_datum) {
	fmt.Printf("datum => Id : %d, Type : %d, Length : %d, Hash : %s, Value : %s, Signature : %T\n",
		mess.Id, mess.Type, mess.Length, string(mess.Hash), string(mess.Value), mess.Signature)
}
*/

func printDatum(mess get_datum) {
	fmt.Printf("datum => Id : %d, Type : %d, Length : %d\n",
		mess.Id, mess.Type, mess.Length)
}

/*
 * this function transforms a directory from the system to a directory struct
 */
func dirToMerkle(path string) directory {
	myDir := directory{}
	dirEntries, err := os.ReadDir(path)
	if err != nil {
		fmt.Println("Error with path "+path+" to convert into a directory :", err)
		return directory{}
	}

	myDir.NbChilds = len(dirEntries)
	myDir.COrTOrD = make([]int, 0)
	myDir.Trees = make([]tree, 0)
	myDir.Chunks = make([]chunk, 0)
	myDir.EntryHashs = make([][32]byte, 0)
	myDir.EntryNames = make([]string, 0)
	//We iterate on all the entries of the path
	for i := 0; i < len(dirEntries); i++ {
		//We add the name (and cut it if it's more than 32 bytes)
		entName := dirEntries[i].Name()
		if len(entName) > 32 {
			entName = entName[:32]
		}
		myDir.EntryNames = append(myDir.EntryNames, entName)

		//if the entry is a directory
		if dirEntries[i].IsDir() {
			d := dirToMerkle(path + "/" + dirEntries[i].Name())
			myDir.COrTOrD = append(myDir.COrTOrD, 2)
			myDir.Trees = append(myDir.Trees, tree{})
			myDir.Chunks = append(myDir.Chunks, chunk{})
			myDir.Directories = append(myDir.Directories, d)
			myDir.EntryHashs = append(myDir.EntryHashs, myDir.Directories[i].Hash)

		} else { //If the entry is a file
			t, c := fileToMerkle(path + "/" + dirEntries[i].Name())
			if t != nil {
				myDir.COrTOrD = append(myDir.COrTOrD, 1)
				myDir.Trees = append(myDir.Trees, *t)
				myDir.Chunks = append(myDir.Chunks, chunk{})
				myDir.Directories = append(myDir.Directories, directory{})
				myDir.EntryHashs = append(myDir.EntryHashs, myDir.Trees[i].Hash)
			} else if c != nil {
				myDir.COrTOrD = append(myDir.COrTOrD, 0)
				myDir.Trees = append(myDir.Trees, tree{})
				myDir.Chunks = append(myDir.Chunks, *c)
				myDir.Directories = append(myDir.Directories, directory{})
				myDir.EntryHashs = append(myDir.EntryHashs, myDir.Chunks[i].Hash)
			} else {
				myDir.COrTOrD = append(myDir.COrTOrD, -1)
				myDir.Trees = append(myDir.Trees, tree{})
				myDir.Chunks = append(myDir.Chunks, *c)
				myDir.Directories = append(myDir.Directories, directory{})
				myDir.EntryHashs = append(myDir.EntryHashs, sha256.Sum256(make([]byte, 0)))
			}
		}
	}
	//We assign the data value of the dir
	myDir.Data = make([]byte, 1)
	//data type
	myDir.Data[0] = 2
	for i := 0; i < myDir.NbChilds; i++ {
		//name
		nameInBytes := []byte(myDir.EntryNames[i])
		paddLen := 32 - len(nameInBytes)
		padding := make([]byte, 0)
		if paddLen > 0 {
			padding = make([]byte, paddLen)
		}
		nameInBytes = append(nameInBytes, padding...)
		myDir.Data = append(myDir.Data, nameInBytes...)
		//hash
		myDir.Data = append(myDir.Data, myDir.EntryHashs[i][:]...)
	}

	//We enter the hash value of the directory
	myDir.Hash = sha256.Sum256(myDir.Data)
	return myDir
}

/*
 * This function takes a path and transforms the file into a tree or a chunk
 */
func fileToMerkle(path string) (*tree, *chunk) {

	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("Error with path "+path+" to convert into a tree/chunk :", err)
		return nil, nil
	}
	T, C := byteArrayToTree(data)

	return T, C
}

/*
 * This function recursively transforms a byte array to a tree or a chunk
 * returns a tuple of pointers (nil, *chunk) or (*tree, nil) depending on if it's a chunk or a tree
 */
func byteArrayToTree(array []byte) (*tree, *chunk) {
	T := &tree{}
	C := &chunk{}

	//If it's a tree
	if len(array) > 1024 {
		nbChilds := 0

		nbChunks := int(math.Ceil(float64(len(array)) / float64(1024)))
		windowRight := 1024
		remaining := array
		for i := 0; i < nbChunks-1; i++ {
			t, c := byteArrayToTree(array[i*1024 : windowRight])
			remaining = array[windowRight:]
			if t != nil {
				T.COrT = append(T.COrT, 1)
				T.Chunks = append(T.Chunks, chunk{})
				T.Trees = append(T.Trees, *t)
			} else if c != nil {
				T.COrT = append(T.COrT, 0)
				T.Chunks = append(T.Chunks, *c)
				T.Trees = append(T.Trees, tree{})
			} else {
				T.COrT = append(T.COrT, -1)
				T.Chunks = append(T.Chunks, chunk{})
				T.Trees = append(T.Trees, tree{})
			}
			windowRight = windowRight + 1024
			nbChilds++
		}

		remaining = array[windowRight-1024:]
		t, c := byteArrayToTree(remaining)
		if t != nil {
			T.COrT = append(T.COrT, 1)
			T.Chunks = append(T.Chunks, chunk{})
			T.Trees = append(T.Trees, *t)
		} else if c != nil {
			T.COrT = append(T.COrT, 0)
			T.Chunks = append(T.Chunks, *c)
			T.Trees = append(T.Trees, tree{})
		} else {
			T.COrT = append(T.COrT, -1)
			T.Chunks = append(T.Chunks, chunk{})
			T.Trees = append(T.Trees, tree{})
		}
		nbChilds++

		//Assigning data value
		T.Data = make([]byte, 1)
		T.Data[0] = 1
		for k := 0; k < nbChilds; k++ {
			switch T.COrT[k] {
			case 0:
				T.Data = append(T.Data, T.Chunks[k].Hash[:]...)
				break
			case 1:
				T.Data = append(T.Data, T.Trees[k].Hash[:]...)
				break
			default:
				break
			}
		}

		//assigning hash value
		T.Hash = sha256.Sum256(T.Data)
		T.NbChilds = nbChilds
		return T, nil

	} else { //If its a chunk
		typeByte := make([]byte, 1)
		typeByte[0] = 0
		C.Data = typeByte
		C.Data = append(C.Data, array...)
		C.Hash = sha256.Sum256(C.Data)

		return nil, C
	}
}

/*
 * This function searches for the hash in our Merkle's tree and sends back its value and hash.
 * returns true if the value was found, false otherwise...
 * Set the last 3 parameters to nil to start a research from our root directory
 */
func searchHash(hashToSearch [32]byte, currDir *directory, currTree *tree, currChunk *chunk) ([32]byte, []byte, bool) {
	var hashRes [32]byte
	var dataRes []byte
	var found bool
	if currDir != nil {
		// hash found !
		if bytes.Compare(hashToSearch[:], currDir.Hash[:]) == 0 {
			return currDir.Hash, currDir.Data, true
		}
		for i := 0; i < currDir.NbChilds; i++ {
			a := currDir.COrTOrD[i]
			switch a {
			case 0:
				hashRes, dataRes, found = searchHash(hashToSearch, nil, nil, &currDir.Chunks[i])
				break
			case 1:
				hashRes, dataRes, found = searchHash(hashToSearch, nil, &currDir.Trees[i], nil)
				break
			case 2:
				hashRes, dataRes, found = searchHash(hashToSearch, &currDir.Directories[i], nil, nil)
				break
			default:
				break
			}
			if found {
				return hashRes, dataRes, found
			}
		}
	} else if currTree != nil {
		// hash found !
		if bytes.Compare(hashToSearch[:], currTree.Hash[:]) == 0 {
			return currTree.Hash, currTree.Data, true
		}
		for i := 0; i < currTree.NbChilds; i++ {
			a := currTree.COrT[i]
			switch a {
			case 0:
				hashRes, dataRes, found = searchHash(hashToSearch, nil, nil, &currTree.Chunks[i])
				break
			case 1:
				hashRes, dataRes, found = searchHash(hashToSearch, nil, &currTree.Trees[i], nil)
				break
			default:
				break
			}
			if found {
				return hashRes, dataRes, found
			}
		}

	} else if currChunk != nil {
		// hash found !
		if bytes.Compare(hashToSearch[:], currChunk.Hash[:]) == 0 {
			return currChunk.Hash, currChunk.Data, true
		}
	} else {
		hashRes, dataRes, found = searchHash(hashToSearch, &localDir, nil, nil)
		return hashRes, dataRes, found
	}

	return [32]byte{}, make([]byte, 0), false
}

/**
*	This function return the calculation signature of data []byte
*
 */
func calcul_signature(data []byte) []byte {
	hashed := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashed[:])
	if err != nil {
		fmt.Println("error Sign calcul_signature")
		fmt.Println(err)
	}
	var signature [64]byte
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signature[:]
}

/**
*	This function return the signature of the data []byte if their is one
*
 */
func getSignature(data []byte) []byte {
	var res [64]byte
	taille := len(data)
	copy(res[:], data[:taille])
	for i := 0; i < len(res); i++ {
		if res[i] != 0 { // on regarde si il y a une signature
			return res[:]
		}
	}
	return nil
}

/**
*	This function check if the signature of a message is correct
*
 */
func check_signature(data []byte, cle_peer peer_key) bool {
	data_stru := byteArrayToMessageStruct(data)
	if data_stru.Signature == nil || len(data_stru.Signature) != 64 || len(cle_peer.key) != 64 {
		return true
	}
	if len(data_stru.Signature) != 64 {
		if debug {
			fmt.Println("la taille de la clé n'est pas correct")
			fmt.Println(data_stru.Signature)
		}
		return true
	}
	var r, s big.Int
	r.SetBytes(data_stru.Signature[:32])
	s.SetBytes(data_stru.Signature[32:])
	taille := binary.BigEndian.Uint16(data[5:7])
	hashed := sha256.Sum256(data[:7+taille])
	var x, y big.Int
	x.SetBytes(cle_peer.key[:32])
	y.SetBytes(cle_peer.key[32:])
	cle_public := ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     &x,
		Y:     &y,
	}
	ok := ecdsa.Verify(&cle_public, hashed[:], &r, &s)
	return ok
}
