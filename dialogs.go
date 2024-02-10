package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
	//"strconv"
)

var target_id uint32
var datum_id uint32
var wait_message_libre bool
var target_message []byte
var target_peer string
var mon_nom = "Xx_DarkSasuke_xXZZ"
var all_connection []peer_connected

var serveur_adresse string

/**
* This function is to make and hello exchange, it send the message hello and return true hello reply is received
* And try it to all the addresses of the peer one by one if the previous one dont work
 */
func hello_exchange(conn *net.UDPConn, addr []string, limit_of_try bool, server_connect bool) bool {
	if debug {
		fmt.Println("nombre d'adresses du pair : ", len(addr))
	}
	for i := 0; i < len(addr); i++ { // on essaie sur toutes les addresses du pair
		addr1, err := net.ResolveUDPAddr("udp", addr[i]) // adresse de la personne avec qui communiquer
		if err != nil {
			fmt.Println("erreur net.ResolveUDPAddr dans enregistrement serveur")
			fmt.Println(err)
		}
		id := rand.Uint32()
		hello := hello_message{Id: id, Type: 2, Length: uint16(len(mon_nom) + 4), Name: mon_nom}
		req := helloToByte(hello)
		target_id = id
		recu := false
		envoyer := false
		j := 0
		for !recu {
			j++
			if limit_of_try {
				if j > 2 {
					break
				}
			}
			for i := 0; i < 3; i++ { // on fait au plus 3 tentative pour envoyer le message
				envoyer = send_message(req, conn, addr1)
				if envoyer {
					break
				}
			}
			if !envoyer {
				fmt.Println("le hello n'a pas pu etre envoyer")
				continue
			}
			for !wait_message_libre {
				//wait
			}
			wait_message_libre = false
			reponse := wait_message(75)
			wait_message_libre = true
			if reponse != nil {
				reponse_struct := byteArrayToHelloStruct(reponse)
				if reponse_struct.Type != 129 {
					continue
				}
				recu = true
				tmp_cle := getPeerKey(reponse_struct.Name)
				if check_signature(reponse, tmp_cle) {

					if server_connect {
						serveur_adresse = addr[i]
					}
					add_peer(tmp_cle)

					return true
				} else {
					return false
				}
			}
		}
	}
	return false
}

/**
* This function set the deadline to receive a message
*
 */
func wait_message(limit int) []byte {
	deadline := 0
	for target_message == nil {
		time.Sleep(50 * time.Millisecond)
		if deadline > limit { // si on arrive a 8 cela signifie que target_message est toujours nil au bout de 2 seconde donc on s'arrete
			fmt.Println("la deadline a été dépassée")
			break
		}
		deadline++
	}
	resultat := target_message
	target_message = nil
	return resultat
}

/**
* This function just print the body of an error message received
*
 */
func errorReceive(mess message) {
	fmt.Println("Error : ", mess.Body)
}

/**
* 	This function send the getDatum request with the hash in parameter and wait for the response
*	If the hash in parameter is nil it send the request with the root of the peer
 */
func askData(conn *net.UDPConn, peer string, hash []byte) (bool, get_datum) {
	//datum := get_datum{Id: 8, Type: 5, Length: r.Length, Hash: []byte(r.Body)}
	if hash == nil || len(hash) < 32 {
		recved, rootAck := getPeerRoot(peer)
		if !rootAck {
			fmt.Println("le pair n'a pas de root")
			return false, get_datum{}
		}
		hash = recved.root
		if len(hash) == 0 {
			fmt.Println("le root recu est de taille 0")
			return false, get_datum{}
		}
	}
	addr := getPeerAddresses(peer)
	id := rand.Uint32()
	datum := get_datum{Id: id, Type: 5, Length: uint16(len(hash)), Hash: hash}
	reqDatum := getDatumToByteArray(datum)
	datum_id = id
	for i := 0; i < len(addr); i++ {
		addr1, err := net.ResolveUDPAddr("udp", addr[i]) // adresse de la personne avec qui communiquer
		if err != nil {
			fmt.Println("erreur ResolveUDPAddr dans askData")
			fmt.Println(err)
		}
		for j := 0; j < 3; j++ {
			envoyer := send_message(reqDatum, conn, addr1)
			if !envoyer {
				fmt.Println("l'envoie du message getDatum n'a pas pu etre effectué")
				continue
			}

			for !wait_message_libre {
			}
			wait_message_libre = false
			message_recu := wait_message(75)
			wait_message_libre = true
			if message_recu == nil {
				if debug {
					fmt.Println("message recu a get_datum est nil")
				}
				continue
			}
			if message_recu[4] == 128 {
				fmt.Println("ErrorReply : " + string(message_recu))
				return false, get_datum{}
			}
			datum_recu := byteArrayToGetDatumStruct(message_recu)
			if datum_recu.Type == 133 {
				fmt.Println("peer does not have the data")
				return false, datum_recu
			}
			if datum_recu.Type == 132 {
				all_data := make([]byte, 0)
				all_data = append(all_data, datum_recu.DatumType)
				all_data = append(all_data, datum_recu.Value...)
				data_value_hashed := sha256.Sum256(all_data)
				//We check the hash
				if bytes.Compare(datum_recu.Hash, hash) != 0 || bytes.Compare(hash, data_value_hashed[:]) != 0 {
					fmt.Println("data corrupted")
					return false, datum_recu
				}

				return true, datum_recu
			}
		}
	}
	return false, get_datum{}
}

/**
 * This function unravels a tree and returns its content under the form of a byte array
 * (so that it can be copied to a fil or displayed in the console)
 */
func exploreTree(hash []byte, conn *net.UDPConn, addr *net.UDPAddr) []byte {
	res := make([]byte, 0)

	//We send the request to get the value of current hash
	dataRequest := make([]byte, 7)
	id := rand.Uint32()
	datum_id = id
	binary.BigEndian.PutUint32(dataRequest[0:4], id)
	dataRequest[4] = 5
	binary.BigEndian.PutUint16(dataRequest[5:7], 32)
	dataRequest = append(dataRequest, hash...)
	recu := false
	backoff := 20
	for !recu {
		envoyer := send_message(dataRequest, conn, addr)
		if !envoyer {
			continue
		}
		for !wait_message_libre {
		}
		wait_message_libre = false
		dataObtained := wait_message(backoff)
		wait_message_libre = true
		if backoff > 1000 {
			return nil
		}
		backoff = backoff * 2
		if dataObtained == nil {
			fmt.Println("##### no answer from the pair : " + string(dataObtained) + "#####")
			continue
		} else {
			recu = true
		}
		if dataObtained[4] == 133 {
			fmt.Println("peer does not have the value")
			return nil
		} else if dataObtained[4] != 132 {
			mess := byteArrayToMessageStruct(dataObtained)
			fmt.Println("Could not get the requested value : ", string(mess.Body))
			continue
		}
		data := byteArrayToGetDatumStruct(dataObtained)
		all_data := make([]byte, 0)
		all_data = append(all_data, data.DatumType)
		all_data = append(all_data, data.Value...)
		data_value_hashed := sha256.Sum256(all_data)
		if bytes.Compare(hash, data.Hash) != 0 || bytes.Compare(hash, data_value_hashed[:]) != 0 {
			fmt.Println("a hash was corrupted")
			return nil
		}

		//if it is a chunk
		effectiveDataLen := binary.BigEndian.Uint16(dataObtained[5:7]) - 32 - 1
		if dataObtained[39] == 0 {
			res = dataObtained[40 : 40+effectiveDataLen]
		} else if dataObtained[39] == 1 { //if it's a tree
			nbHash := int(effectiveDataLen) / 32
			fmt.Print(".")
			for i := 0; i < nbHash; i++ {
				var dataToAppend []byte
				dataToAppend = nil
				dataToAppend = exploreTree(dataObtained[40+(i*32):40+(i*32)+32], conn, addr)
				if dataToAppend == nil {
					fmt.Println("dataToAppend is nil")
					return nil
				}

				res = append(res, dataToAppend...)
			}
		} else {
			//If it's not a tree or a chunk, we don't know what it is
			fmt.Println("it is not a chunk or a tree")
			return nil
		}
	}
	return res
}

/**
*	This function reads all the messages we received, and checks if the id of the messages match with the target_id of a request we made,
*	Or if the peer match in case of a nat traversal request
*	Or in other case , respond to the request we made
 */
func receive_message(conn *net.UDPConn) {
	for true {
		mess_recu := make([]byte, messageBufSize)
		conn.SetReadDeadline(time.Now().Add(700))
		n, addr, err := conn.ReadFrom(mess_recu)
		if n < 7 {
			continue
		}
		if err != nil {
			fmt.Println("erreur ReadFrom receive_message")
			fmt.Println(err)
		}
		if debug {
			printMessage(byteArrayToMessageStruct(mess_recu))
		}
		id_message_recu := binary.BigEndian.Uint32(mess_recu[:4])
		if id_message_recu == target_id {
			for target_message != nil {
				time.Sleep(50 * time.Millisecond)
				if debug {
					fmt.Println("target_id ok : ", target_id)
					fmt.Println("on attend que target_message soit vide. target_message actuel : " + string(target_message))
				}
			}
			target_message = mess_recu
		} else if id_message_recu == datum_id {
			for target_message != nil {
				time.Sleep(250 * time.Millisecond)
				if debug {
					fmt.Println("datum_id ok : ", datum_id)
					fmt.Println("on attend que target_message soit vide. target_message actuel : " + string(target_message))
				}
			}
			target_message = mess_recu
		} else if addr.String() == target_peer {
			for target_message != nil {
				time.Sleep(250 * time.Millisecond)
				if debug {
					fmt.Println("target_peer ok : ", target_peer)
					fmt.Println("on attend que target_message soit vide. target_message actuel : " + string(target_message))
				}
			}
			target_message = mess_recu
		} else {
			switch mess_recu[4] {
			case 2:
				message_recu := byteArrayToHelloStruct(mess_recu)
				reponse := hello_message{Id: message_recu.Id, Type: 129, Length: uint16(len(mon_nom) + 4), Name: mon_nom}
				cle_peer := getPeerKey(message_recu.Name)
				if check_signature(mess_recu, cle_peer) {
					add_peer(cle_peer)
					envoyer := false
					limit := 5
					for !envoyer && limit > 0 {
						envoyer = send_message(helloToByte(reponse), conn, addr)
						limit--
					}
				}
				break
			case 3:
				cle_peer := getPeerConnected(addr.String())
				if cle_peer.peer != "" {
					if check_signature(mess_recu, cle_peer) {
						message_recu := byteArrayToMessageStruct(mess_recu)
						formatted := make([]byte, 64)
						publicKey.X.FillBytes(formatted[:32])
						publicKey.Y.FillBytes(formatted[32:])
						reponse := message{Id: message_recu.Id, Type: 130, Length: 64 /*0*/, Body: formatted}
						envoyer := false
						limit := 5
						for !envoyer && limit > 0 {
							envoyer = send_message(messageToByte(reponse), conn, addr)
							limit--
						}
					} else {
						fmt.Println("la signature n'est pas respecter par le message de " + cle_peer.peer)
					}
				}
				break
			case 4:
				cle_peer := getPeerConnected(addr.String())
				if cle_peer.peer != "" {
					if check_signature(mess_recu, cle_peer) {
						message_recu := byteArrayToMessageStruct(mess_recu)
						reponse := message{Id: message_recu.Id, Type: 131, Length: uint16(32), Body: localDir.Hash[:]}
						envoyer := false
						limit := 5
						for !envoyer && limit > 0 {
							envoyer = send_message(messageToByte(reponse), conn, addr)
							limit--
						}
					} else {
						fmt.Println("la signature n'est pas respecter par le message de " + cle_peer.peer)
					}
				}
				break
			case 5:
				message_recu := byteArrayToGetDatumStruct(mess_recu)
				var hash_recu [32]byte
				copy(hash_recu[:], message_recu.Hash)
				h, d, b := searchHash(hash_recu, nil, nil, nil)
				// On prépare un NoDatum
				reponse := get_datum{Id: message_recu.Id, Type: 133, Length: 32, Hash: message_recu.Hash}
				//Si on a trouvé la donnée, on la met dans le datum
				if b {
					reponse.Hash = h[:]
					reponse.Value = d[1:]
					reponse.DatumType = uint8(d[0])
					reponse.Type = 132
					reponse.Length = reponse.Length + uint16(len(d))
				}
				envoyer := false
				limit := 5
				for !envoyer && limit > 0 {
					envoyer = send_message(getDatumToByteArray(reponse), conn, addr)
					limit--
				}
				break
			case 7:
				fmt.Println("NatTraversal received")
				message_recu := byteArrayToMessageStruct(mess_recu)
				target_ip := byte_to_ip(message_recu)
				target_ip_tab := [1]string{target_ip}
				envoyer := hello_exchange(conn, target_ip_tab[:], true, false)
				if envoyer {
					fmt.Println("nous avons recu une demande de tarversé de nat et nous avons fait un hello_exchange")
				} else {
					fmt.Println("nous avons recu une demande de tarversé de nat mais le hello exchange a échoué")
				}
				break
			case 0:
				fmt.Println("NoOp recu")
				break
			case 1:
				message_recu := byteArrayToMessageStruct(mess_recu)
				fmt.Println(addr, " a envoyé : ", string(message_recu.Body))
				break
			case 128:
				fmt.Println("ErrorReply received : ", string(mess_recu[7:]))
				break
			default:
				if debug {
					fmt.Println("message inattendu de ", addr, " de type ", mess_recu[4])
				}
				break
			}
		}
	}
}

/**
* 	This function send the message mess to the peer addr
*
 */
func send_message(mess []byte, conn *net.UDPConn, addr net.Addr) bool {
	if debug {
		fmt.Println("on envoie le message")
		printMessage(byteArrayToMessageStruct(mess))
	}
	n, err := conn.WriteTo(mess, addr)
	success := true
	if n == 0 {
		fmt.Println("le contenu du message + " + string(mess) + " n'a pas pu être envoyé")
		fmt.Println("type : ", mess[7])
		success = false
	}
	if err != nil {
		fmt.Println("erreur WriteTo send_message")
		fmt.Println(err)
		success = false
	}
	return success
}

/*
 * This function downloads a file given its path
 * The path must be under the form of "/path/to/file.foo"
 * returns -1 in case of error (file not found or error downloading)
 * returns 0 if everything is alright
 */
func downloadWithPath(path string, currHash []byte, target_peer string, conn *net.UDPConn, target_addr *net.UDPAddr) int {
	pathSteps := strings.Split(path, "/")
	currStep := ""
	for i := 0; i < len(pathSteps); i++ {
		currStep = currStep + "/" + pathSteps[i]
		dirContent, dirHashs := getDirectory(currHash)
		index := indexOf(pathSteps[i], dirContent)
		if index == -1 {
			fmt.Println("Wrong path : " + currStep + " not found...")
			return -1
		} else {
			currHash = dirHashs[index]
		}
		_, currData := askData(conn, target_peer, currHash)

		switch currData.DatumType {
		case 0, 1:
			res := exploreTree(currData.Hash, conn, target_addr)
			file, errFile := os.Create("./" + pathSteps[i])
			if errFile != nil {
				fmt.Println("erreur de creation : ", errFile)
			}
			_, errWrite := file.Write(res)
			if errWrite != nil {
				fmt.Println("Couldn't write file", errWrite)
				return -1
			} else {
				fmt.Println("file downloaded : ", currStep)
			}
			return 0
		case 2:
			currHash = currData.Value
		default:
			fmt.Println("type de donnée non supporté")
		}
	}
	return -1
}

/*
 * This function returns the index of requested pattern in the list
 * returns -1 if not found
 */
func indexOf(pattern string, list []string) int {
	k := 0
	for _, r := range list {
		if r == pattern {
			return k
		}
		k++
	}
	return -1
}

/**
* This function add a peer to the global variable all_connection
*
 */
func add_peer(peer_n peer_key) {
	est_present := false
	for i := 0; i < len(all_connection); i++ {
		if peer_n.peer == all_connection[i].public_key_peer.peer {
			est_present = true
			break
		}
	}
	if !est_present {
		all_connection = append(all_connection, peer_connected{adresse_peer: getPeerAddresses(peer_n.peer), public_key_peer: peer_n})
	}
}

/**
*	This function return le value peer_key
*
 */
func getPeerConnected(addr string) peer_key {
	for i := 0; i < len(all_connection); i++ {
		for j := 0; j < len(all_connection[i].adresse_peer); j++ {
			if all_connection[i].adresse_peer[j] == addr {
				return all_connection[i].public_key_peer
			}
		}
	}
	return peer_key{}
}
