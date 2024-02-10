package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"crypto/rand"
	mrand "math/rand"
)

const messageBufSize = 1200
const pathToLocalData = "./localData/"

var localDir directory

var debug bool
var enregistrer bool
var enregistrement_failed bool
var privateKey *ecdsa.PrivateKey
var publicKey *ecdsa.PublicKey

// server is off
var server_name = "name_of_the_server"

/*
*	This function maintain the connection to the server by sending periodically an hello message
*
 */
func enregistrementRun(conn *net.UDPConn, addr []string) {
	for true {
		if debug {
			fmt.Println("je vais m'enregistrer")
		}
		enregistrer = hello_exchange(conn, addr, false, true)
		if !enregistrer {
			enregistrement_failed = true
		}
		time.Sleep(1 * time.Minute)
	}
}

func main() {
	var err error
	privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fmt.Println("error when generating privateKey")
		return
	}
	publicKey, _ = privateKey.Public().(*ecdsa.PublicKey)
	datum_id = mrand.Uint32() //Pour éviter que ce soit 0
	localDir = dirToMerkle(pathToLocalData)
	//End tests conversion
	useDebug := flag.Bool("debug", false, "print everything")
	if *useDebug {
		fmt.Println("on va debugger")
		debug = true
	}
	wait_message_libre = true
	enregistrer = false
	enregistrement_failed = false
	//First, we register in the server
	adresse_serveur := getPeerAddresses(server_name)
	mon_adresse := ":" + strconv.Itoa(8080)
	addr2, err := net.ResolveUDPAddr("udp", mon_adresse) // mon adresse (port sur lequel je veux lire les message)

	if err != nil {
		fmt.Println(err)
	}
	conn, err := net.ListenUDP("udp", addr2)

	go receive_message(conn)
	go enregistrementRun(conn, adresse_serveur)

	for true {
		if !enregistrer { // si  on est pas encore enregistrer
			if debug {
				fmt.Println("on attend que l'enregistrement se fasse")
			}
			if enregistrement_failed { // si on a tenté de s'enregistrer mais que sa a échoué
				fmt.Println("l'enregistrement aupres du serveur a échoué")
				return
			}
			time.Sleep(1 * time.Second)
			continue
		}
		fmt.Println("Printing registered pairs in the server")
		peers := getPeers()
		for i := 0; i < len(peers); i++ {
			fmt.Println(strconv.Itoa(i) + " - " + string(peers[i]))
		}

		//We select a pair (registered in the server)
		var peer_selected int
		fmt.Print("A qui voulez vous demander les données ? (rentrez son numéro) (-1 pour quitter) : ")
		fmt.Scanln(&peer_selected)
		if peer_selected >= len(peers) {
			continue
		} else if peer_selected < 0 {
			break
		}
		fmt.Println("pair demandé : ", peers[peer_selected])

		//Now, we ask the pair's root (to the server)
		pAddr := getPeerAddresses(peers[peer_selected])
		if len(pAddr) == 0 {
			fmt.Println("Peer doesn't give any adress...")
			continue
		}
		target_name := pAddr[0]
		target_root, ackRoot := getPeerRoot(peers[peer_selected])
		target_addr, err := net.ResolveUDPAddr("udp", target_name) //We only use the pair's first address
		if err != nil {
			fmt.Println(err)
		}
		if !ackRoot {
			fmt.Println("Asked root from " + target_name + "was not received...")
			continue
		}

		hello := natTraversal(peers[peer_selected], conn)
		if !hello {
			fmt.Println("connexion to peer failed")
			continue
		}
		fmt.Println("la tarverser de nat a reussi")
		time.Sleep(250 * time.Millisecond)
		donnees_correct, received := askData(conn, peers[peer_selected], target_root.root)
		if !donnees_correct {
			continue
		}
		fini := false
		res := make([]byte, 0)
		currName := "defaultName"
		for !fini {
			switch received.DatumType {
			case 0, 1:
				res = exploreTree(received.Hash, conn, target_addr)

				if res != nil {
					file, errFile := os.Create(currName)
					if errFile != nil {
						fmt.Println("erreur de creation : ", errFile)
					}
					if _, errWrite := file.Write(res); errWrite != nil {
						fmt.Println("Couldn't write file", errWrite)
					} else {
						fmt.Println("file downloaded : ", currName)
					}
				} else {
					fmt.Println("Couldn't download the file...")
				}
				fini = true
			case 2:
				if exploreDir(received.Value, peers[peer_selected], conn, target_addr) == -1 {
					fini = true
				} else {
					if debug {
						fmt.Println("On continue")
					}
				}
			default:
				fmt.Println("type de donnée non supporté")
			}
		}
	}
}

func exploreDir(dirData []byte, target_peer string, conn *net.UDPConn, target_addr *net.UDPAddr) int {
	dir := make([]string, 0)
	var hashs [][]byte
	choice := -1
	res := make([]byte, 0)
	currName := "defaultName"
	res = dirData

	for true {
		dir, hashs = getDirectory(res)
		printDir(dir)
		fmt.Println(strconv.Itoa(len(dir)) + " - write your path")
		//We ask the user which data he wants
		fmt.Println("Quelle donnée demander ? (-1 to return) : ")
		choice = -1
		fmt.Scanln(&choice)
		if choice > len(dir) {
			return -1
		} else if choice < 0 {
			return -1
		} else if choice == len(dir) {
			var path string
			fmt.Scanln(&path)
			return downloadWithPath(path, dirData, target_peer, conn, target_addr)
		}
		donnees_correct, received := askData(conn, target_peer, hashs[choice])
		currName = dir[choice]
		if !donnees_correct {
			return -1
		}

		switch received.DatumType {
		case 0, 1:
			res = exploreTree(received.Hash, conn, target_addr)

			if res != nil {
				file, errFile := os.Create("./" + currName)
				if errFile != nil {
					fmt.Println("erreur de creation : ", errFile)
				}
				_, errWrite := file.Write(res)
				if errWrite != nil {
					fmt.Println("Couldn't write file", errWrite)
				} else {
					fmt.Println("file downloaded : ", "./"+currName)
				}
			} else {
				fmt.Println("Couldn't download the file...")
			}
			return 0
		case 2:
			exploreDir(received.Value, target_peer, conn, target_addr)
		default:
			fmt.Println("type de donnée non supporté")
		}
	}
	return -1
}

func getPeers() []string {
	transport := &*http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}

	req, err := http.NewRequest("GET", "https://"+server_name+":8443/peers/", nil)

	if err != nil {
		fmt.Println(err)
	}

	resultat, err := client.Do(req)

	if err != nil {
		fmt.Println(err)
	}

	if resultat.StatusCode == 200 {

		defer resultat.Body.Close()
		tab, err := io.ReadAll(resultat.Body)

		if err != nil {
			fmt.Println(err)
		}

		all_peers := strings.Split(string(tab), "\n")

		if len(all_peers) > 0 {
			return all_peers[:len(all_peers)-1]
		} else {
			return all_peers
		}
	} else {
		return nil
	}

}

func getPeerKey(peers string) peer_key {
	transport := &*http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}

	r, err := http.NewRequest("GET", "https://"+server_name+":8443/peers/"+peers+"/key", nil)

	if err != nil {
		fmt.Println(err)
	}

	req, err := client.Do(r)

	if err != nil {
		fmt.Println(err)
	}

	switch code := req.StatusCode; code {
	case 404:
		fmt.Println("pair inconnu")
		return peer_key{}
	case 204:
		fmt.Println("cle du pair inconnu")
		return peer_key{peer: peers, key: nil}
	case 200:
		defer req.Body.Close()
		tab, err := io.ReadAll(req.Body)

		if err != nil {
			fmt.Println(err)
		}
		return peer_key{peer: peers, key: tab}

	default:
		fmt.Println("code erreur inconnu")
		return peer_key{}
	}

}

func getPeerAddresses(peers string) []string {
	transport := &*http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}

	r, err := http.NewRequest("GET", "https://"+server_name+"/peers/"+peers+"/addresses", nil)

	if err != nil {
		fmt.Println(err)
	}

	req, err := client.Do(r)

	if req == nil {
		fmt.Println("req nil, le pair n'a pas d'adresse")
	}

	if req.StatusCode == 200 {

		defer req.Body.Close()
		tab, err := io.ReadAll(req.Body)

		if err != nil {
			fmt.Println(err)
		}

		all_addresse := strings.Split(string(tab), "\n")
		res := make([]string, 0)
		for i := 0; i < len(all_addresse); i++ {
			if all_addresse[i] != "" {
				res = append(res, all_addresse[i])
			}
		}

		if debug {
			fmt.Println("addresses du pair : " + peers)
			for i := 0; i < len(all_addresse); i++ {
				fmt.Println(all_addresse[i])
			}

		}

		return res
	} else {
		return nil
	}

}

func getPeerRoot(peers string) (peer_root, bool) {
	transport := &*http.DefaultTransport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	client := &http.Client{
		Transport: transport,
		Timeout:   50 * time.Second,
	}
	req, err := client.Get("https://" + server_name + ":8443/peers/" + peers + "/root")

	if err != nil {
		fmt.Println(err)
	}

	switch code := req.StatusCode; code {
	case 404:
		fmt.Println("pair inconnu")
		return peer_root{}, false
	case 204:
		fmt.Println("racine du pair inconnu")
		return peer_root{peer: peers}, false
	case 200:
		defer req.Body.Close()
		tab, err := io.ReadAll(req.Body)

		if err != nil {
			fmt.Println(err)
		}

		return peer_root{peers, tab}, true

	default:
		fmt.Println("code erreur inconnu")
		return peer_root{}, false
	}
}

func peerPresent(tab []string, moi string) bool {
	for i := 0; i < len(tab); i++ {
		if tab[i] == moi {
			return true
		}
	}
	return false
}

/**
* 	This function try to send an hello message to the peer
*
 */
func tryHello(peer string, conn *net.UDPConn) bool {
	peer_addr := getPeerAddresses(peer)

	conn_reussi := hello_exchange(conn, peer_addr, true, false)
	if conn_reussi {
		return true
	}
	return false
}

/**
*	This function try to send an hello, and if hello reply is not received
*	It starts nat traversal
 */
func natTraversal(peer string, conn *net.UDPConn) bool {
	if !tryHello(peer, conn) {
		fmt.Println("on va commencer la traverser de nat")
		peer_addr := getPeerAddresses(peer)
		serv_addr, err := net.ResolveUDPAddr("udp", serveur_adresse)
		if err != nil {
			fmt.Println("erreur ResolveUDPAddr natTraversal")
			fmt.Println(err)
		}
		for j := 0; j < len(peer_addr); j++ {
			taille := ip_len(peer_addr[j])
			var body []byte
			if taille == 6 {
				body = ipv4_to_byte(peer_addr[j])
			} else if taille == 18 {
				body = ipv6_to_byte(peer_addr[j])
			} else {
				return false
			}
			id := mrand.Uint32()
			target_peer = peer_addr[j]
			message_to_send := message{Id: id, Type: 6, Length: uint16(taille), Body: body}
			envoyer := false
			limit := 5
			for !envoyer && limit > 0 {
				fmt.Println("NATTraversal sending")
				envoyer = send_message(messageToByte(message_to_send), conn, serv_addr)
				limit--
			}
			for i := 0; i < 2; i++ {
				for !wait_message_libre {
				}
				wait_message_libre = false
				res := wait_message(250)
				wait_message_libre = true
				if res == nil {
					continue
				}
				target_peer = ""
				if res[4] == 2 {
					res_mess := byteArrayToHelloStruct(res)
					if res_mess.Name == peer {
						reponse := hello_message{Id: res_mess.Id, Type: 129, Length: uint16(len(mon_nom) + 4), Name: mon_nom}
						envoyer = false
						limit = 5
						for !envoyer && limit > 0 {
							addr_rep, err := net.ResolveUDPAddr("udp", peer_addr[j])
							if err != nil {
								fmt.Println("erreur ResolveUDPAddr natTraversal")
								fmt.Println(err)
							}
							envoyer = send_message(helloToByte(reponse), conn, addr_rep)
							limit--
						}
						mypeer := [1]string{peer_addr[j]}
						return hello_exchange(conn, mypeer[:], true, false)
					}
				}
			}
			fmt.Println("nous n'avons pas recu le hello")
		}
		//}
	} else {
		return true
	}
	return false
}

/**
* This function return the length of the socket addresses (to know if it is ipv4 or ipv6)
*
 */
func ip_len(s string) int {
	if strings.Contains(s, "[") && strings.Contains(s, "]") {
		return 18
	} else {
		return 6
	}
}

func ipv4_to_byte(addr string) []byte {
	udp_addr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Println("erreur ResolveUDPAddr ipv4_to_byte")
		fmt.Println(err)
	}
	res := udp_addr.IP.To4()
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(udp_addr.Port))
	resultat := append([]byte(res), port...)
	return resultat
}

func ipv6_to_byte(addr string) []byte {
	udp_addr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Println("erreur ResolveUDPAddr ipv6_to_byte")
		fmt.Println(err)
	}
	res := udp_addr.IP.To16()
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(udp_addr.Port))
	res = append(res, port...)
	return []byte(res)
}

func byte_to_ip(mess message) string {
	taille := mess.Length
	var addr net.IP
	addr = mess.Body
	ip := addr[:taille-2].String()
	port := binary.BigEndian.Uint16(mess.Body[taille-2:])
	if strings.Contains(ip, ":") {
		ip = "[" + ip + "]"
	}
	return ip + ":" + strconv.Itoa(int(port))
}
