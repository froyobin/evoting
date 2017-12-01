package main

import (
	"fmt"
	"github.com/roasbeef/go-go-gadget-paillier"
	"encoding/json"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"bytes"
	"io/ioutil"
	"bufio"
	"os"
	"time"
	"math/big"
	"io"
	"strconv"
	mathrand "math/rand"
	"lib"
	pbchain "github.com/hyperledger/fabric/protos"

	"log"
	"flag"
)

const (
	NAME       = "59b24cf3cfc32200f0d63e5226ade100900fba385e958e714b30526be37e79b8ae1577fe04490a8fac954f29b070b1fd0b2af76e74d87f3d6243b600dea00adf"
	ZERO_POOL_SIZE = 4096 //2^20

	VOTED = 2
	NOMATCH = 0
	SUCCESS = 1
	NG_SUCC = 3
	PUB_KEY_SUCC = 4
	ZERO_POOL_SUCC = 5
	RING_ARGS_SUCC = 6
	ADD_BALLOT_SUCC = 8
	GET_RESULT_SUCCESS = 9
	UPLOAD_PLAIN_SUCCESS = 10
	IGNORE = 7
)

type PrivkeyPart struct {
	L []byte
	U []byte
}

type ShortRingPara struct {
	N []byte
	G []byte
	Hpi []byte
	Gpi []byte
}

type CtorMsg struct {
	Function string
	Args [] string
}



type ChainID struct {
	Name string
}

type RespData struct {
	Body []byte
	Status string
}

type Params struct {
	Type int
	ChaincodeId ChainID
	CtorMsg CtorMsg
	SecureContext string
}
type JsonData struct {
	Jsonrpc string
	Method string
	Params Params
	Id string
}
type PublicKey struct {
	N        []byte // modulus
	G        []byte // n+1, since p and q are same length
	NSquared []byte
}

type PubkeySmartKey struct{
	AdminKey PublicKey
	Smartcontractkey []byte
}


type RespStruct struct {
	Jsonrpc string
	Result interface{}
	Id string
}

type BallotPool struct{
	Len int
	Ballots [10][]byte
}


type ResultStruct struct{
	Result [][]byte
}

type NG struct{
	N []byte
	G []byte
}

func timeTrack(start time.Time, name string) {
    elapsed := time.Since(start)
    log.Printf("%s took %s", name, elapsed)
}


func upload(url, functions, method string, args []string)(bool, RespData){

	ChainIDSend := ChainID{NAME}
	CtorMsgSend := CtorMsg{functions, args}
	ParamsSend := Params{1, ChainIDSend, CtorMsgSend,"jim" }
	jsend := JsonData{"2.0", method, ParamsSend,"5"}
	b, err := json.Marshal(jsend)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(b))
	req.Header.Set("X-Custom-Header", "Linux")
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
        panic(err)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	ret := RespData{body,resp.Status}

	if ret.Status == "200 OK"{
		return true, ret
	}else{
		return false, ret
	}

}


func upload_tally_zero_pools(url string, privkey *paillier.PrivateKey)(bool, RespData){

	zero := big.NewInt(0).Bytes()

	zero_pool := make([][]byte, ZERO_POOL_SIZE, ZERO_POOL_SIZE)
	for i:=0;i<ZERO_POOL_SIZE;i++ {
		zero_pool[i],_,_= paillier.Encrypt(&privkey.PublicKey, zero)
	}
	marshed,_ := json.Marshal(zero_pool)
	encoded := base64.StdEncoding.EncodeToString(marshed)
	fmt.Println("length of zero pool", len(encoded))
	args := [] string{encoded}
	ret,retdata := upload(url,"upload_tally_zero_pools", "invoke", args)
	return ret, retdata
}


func upload_pubkey(url string)(*paillier.PrivateKey, bool, RespData){
	privKey, _ := paillier.GenerateKey(rand.Reader, 1024)

	pubkey := PublicKey{privKey.PublicKey.N.Bytes(),privKey.PublicKey.G.Bytes(),
		privKey.PublicKey.NSquared.Bytes()}

	dpubkey,_ := json.Marshal(pubkey)
	bstring := base64.StdEncoding.EncodeToString(dpubkey)
	args := [] string{bstring}
	ret,retData := upload(url,"upload_tally_pubkey", "invoke", args)
	return privKey, ret, retData
}

func decode_message(data []byte)(string){
	var m RespStruct
	json.Unmarshal(data, &m)
	msg := m.Result
	if msg == nil{
		return ""
	}
	ret := msg.(map[string]interface{})
	msgEncoded := ret["message"].(string)
	return msgEncoded
}

func upload_result_plaintext(url string, m[]byte, r []byte)(bool, RespData){
	marshed_base64_m := base64.StdEncoding.EncodeToString(m)
	marshed_base64_r := base64.StdEncoding.EncodeToString(r)

	args := [] string{marshed_base64_m, marshed_base64_r}

	ret, resp := upload(url, "upload_result_plaintext", "invoke", args)
	if ret == false{
		return false, resp
	}


	return true, resp
}


func query_test_blocks(url string, datasize string)(bool, RespData){


	args := [] string{datasize}

	ret, resp := upload(url, "query_test", "query", args)
	fmt.Println("dddd")
	if ret == false{
		return false, resp
	}


	return true, resp
}

func create_test_blocks(url string, datasize,loops string)(bool, RespData){


	args := [] string{datasize, loops}

	ret, resp := upload(url, "create_test_blocks", "invoke", args)
	if ret == false{
		return false, resp
	}


	return true, resp
}

func get_result(url string, privkey * paillier.PrivateKey)(bool,[]byte,[]byte){
	ret, resp := upload(url, "get_result", "query", nil)
	if ret == false{
		return false, nil,nil
	}
	result_msg := decode_message(resp.Body)

	t1, _ := base64.StdEncoding.DecodeString(result_msg)
	err, m,r := calculate_m_r(privkey,t1)
	if err != nil{
		ret = false
	}
	ret = true
	//fixme test for verification
	//mc := new(big.Int).Add(new(big.Int).SetBytes(m), big.NewInt(1))
	return ret, m, r

}


func show_result(url string, numcandidate int)([][]byte){
	ret, resp := upload(url, "show_result", "query", nil)
	if ret == false{
		fmt.Println("error in getting result")
		return nil
	}
	result_msg := decode_message(resp.Body)
	if result_msg == ""{
		fmt.Println("error in getting result")
		return nil
	}
	t1, _ := base64.StdEncoding.DecodeString(result_msg)
	var test2 ResultStruct
	test2.Result = make([][]byte, numcandidate, numcandidate)
	json.Unmarshal(t1, &test2)
	if ret ==true{
		return test2.Result
	}
	return nil
}


func add_vote(url string)(RespData) {
	_, resp := upload(url, "Calculate_ballots", "invoke", nil)
	return resp
}


func Red(msg string)(string){
	return "\x1b[31;1m" + msg + "\x1b[0m"
}


func Blue(msg string)(string){
	return "\x1b[34;1m" + msg + "\x1b[0m"
}


func calculate_m_r(privKey *paillier.PrivateKey, cbyte []byte)(error, []byte,[]byte){

	mbyte,err :=  paillier.Decrypt(privKey, cbyte)
	c := new(big.Int).SetBytes(cbyte)
	m := new(big.Int).SetBytes(mbyte)
	if err != nil {
		return err,nil,nil
	}
	inversem := new(big.Int).ModInverse(new(big.Int).Exp(privKey.G,m, privKey.NSquared), privKey.NSquared)
	rn := new(big.Int).Mul(c, inversem)
	v1 := new(big.Int).ModInverse(privKey.Q,privKey.P)
	v2 := new(big.Int).ModInverse(privKey.P,privKey.Q)

	i1 := new(big.Int).ModInverse(privKey.Q,new(big.Int).Sub(privKey.P, big.NewInt(1)))
	i2 := new(big.Int).ModInverse(privKey.P,new(big.Int).Sub(privKey.Q, big.NewInt(1)))
	a1 := new(big.Int).Exp(rn, i1, privKey.P)
	a2 := new(big.Int).Exp(rn, i2, privKey.Q)
	parta := new(big.Int).Mul(a2,new(big.Int).Mul(v2,privKey.P))
	partb := new(big.Int).Mul(a1,new(big.Int).Mul(v1,privKey.Q))

	calculated_r := new(big.Int).Add(parta, partb)
	calculated_r.Mod(calculated_r,privKey.N)
	return nil, m.Bytes(), calculated_r.Bytes()

}


func GenerateN(random io.Reader, bits int) (*big.Int, *big.Int, error) {
	//one := big.NewInt(1)
	two := big.NewInt(2)
	//pq := make([]*big.Int, 2, 2)
	var N *big.Int
	N,_ = rand.Prime(rand.Reader, bits)
	p, err := rand.Prime(random, bits/2)
			if err != nil {
				return nil,nil,err
			}

	g := new(big.Int).Exp(p, two, N)

	return N,g ,nil
}


func upload_NG_for_voters(url string)(bool, RespData){
	N,g,_ := GenerateN(rand.Reader, 512)

	ng := NG{N.Bytes(),g.Bytes()}
	dpubkey,_ := json.Marshal(ng)
	bstring := base64.StdEncoding.EncodeToString(dpubkey)
	args := [] string{bstring}
	ret, retdata := upload(url,"upload_NG", "invoke", args)
	return ret, retdata
}

func check(e error) {
    if e != nil {
        panic(e)
    }
}

func generate_rand(N *big.Int)(*big.Int){
	randsource := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	r  := new(big.Int).Rand(randsource, N)
	return r
}

func Get_short_ring_params(filename string )(ShortRingPara){

	two := big.NewInt(2)
	N := big.NewInt(0)
	g := big.NewInt(0)
	hpi := big.NewInt(0)
	gpi := big.NewInt(0)

	fi, err := os.Open(filename)
	check(err)
	 defer func() {
        if err := fi.Close(); err != nil {
            panic(err)
        }
    }()
	r := bufio.NewReader(fi)
	for i:=0; i<2;i++{
		line, err := r.ReadBytes('\n')
		if err != nil && err != io.EOF {
			panic(err)
		}
		var m []byte
		json.Unmarshal(line, &m)
		if i == 0 {
			N.Add(big.NewInt(0), new(big.Int).SetBytes(m))
			continue
		}
		if i == 1 {
			g.Add(big.NewInt(0), new(big.Int).SetBytes(m))
			continue
		}
	}

	tmp1 := generate_rand(N)
	tmp2 := generate_rand(N)
	gpi = gpi.Exp(tmp1, two, N)
	hpi = hpi.Exp(tmp2,two,N)

	return ShortRingPara{N.Bytes(),g.Bytes(),hpi.Bytes(), gpi.Bytes()}
}


func upload_ring_param(url string, ring_param ShortRingPara)(bool, RespData){
	dpubkey,_ := json.Marshal(ring_param)
	bstring := base64.StdEncoding.EncodeToString(dpubkey)
	args := [] string{bstring}
	ret, retdata := upload(url,"upload_Ring_Param", "invoke", args)
	return ret, retdata
}

func handle_event_testing(ce *pbchain.Event_ChaincodeEvent)(int){

	    testval := string(ce.ChaincodeEvent.Payload)

	    switch (testval) {
		case "FINISH_UPLOADING_TEST_BLOCK":
			fmt.Println("finishing uploading test")
		    break
	    default:
		    break
	    }
	    return 0
}

func handle_event(ce *pbchain.Event_ChaincodeEvent,retData RespData)(int){

	var m RespStruct
	retval := NOMATCH
	json.Unmarshal(retData.Body, &m)
	msg := m.Result
	ret := msg.(map[string]interface{})
	tid := ret["message"].(string)
	//if ce.ChaincodeEvent.EventName != "ADMIN"{
	//	return IGNORE
	//}
	if tid == ce.ChaincodeEvent.TxID{
		testval := string(ce.ChaincodeEvent.Payload)
		switch (testval) {
		case "ALREADY_VOTED":
			retval = VOTED
			break
		case "CAST SUCCESS":
			retval = SUCCESS
			break
		case "NG SUCCESS":
			retval = NG_SUCC
			break
		case "ZERO POOL SUCCESS":
			retval = ZERO_POOL_SUCC
			break
		case "PUBKEY SUCCESS":
			retval = PUB_KEY_SUCC
			break
		case "RING PARAM SUCCESS":
			retval = RING_ARGS_SUCC
			break
		case "ADDBALLOT SUCCESS":
			retval = ADD_BALLOT_SUCC
			break
		case "GET RESULT SUCCESS":
			retval = GET_RESULT_SUCCESS
			break
		case "UPLOAD PLAINTEXT SUCCESS":
			retval = UPLOAD_PLAIN_SUCCESS
			break
		case "FINISH_UPLOADING_TEST_BLOCK":
			fmt.Println("finishing uploading test")
			break

		}
	}else{
		return NOMATCH
	}
	return retval
}



func get_handle_result(ret_event chan *pbchain.Event_ChaincodeEvent, retData RespData){
		leaveloop := false
		for {
			ce := <-ret_event
			ret := handle_event(ce, retData)
			switch ret {
			case SUCCESS:
				leaveloop  = true
				break
			case VOTED:
				fmt.Println(Red("already voted!!"))
				leaveloop = true
				break
			case NG_SUCC:
				fmt.Println(Blue("NG has been uploaded successfully"))
				leaveloop = true
				break
			case PUB_KEY_SUCC:
				fmt.Println(Blue("Pailler PUB KEY has been uploaded successfully"))
				leaveloop = true
				break
			case ZERO_POOL_SUCC:
				fmt.Println(Blue("ZERO POOL has been uploaded successfully"))
				leaveloop = true
				break
			case RING_ARGS_SUCC:
				fmt.Println(Blue("Ring param has been uploaded successfully"))
				leaveloop = true
				break
			case ADD_BALLOT_SUCC:
				fmt.Println(Blue("Add all ballots successfully"))
				leaveloop = true
				break
			case GET_RESULT_SUCCESS:
				fmt.Println(Blue("GET RESULT SUCCESS"))
				leaveloop = true
				break
			case UPLOAD_PLAIN_SUCCESS:
				fmt.Println(Blue("upload plaintext successfully"))
				leaveloop = true
				break
			case IGNORE:
				leaveloop = true
			default:
				break
			}
			if leaveloop{
				break
			}
			time.Sleep(time.Second*2)
			fmt.Println(Red("waiting for blockchain event"))
		}

}


func handle_response(ret_event chan *pbchain.Event_ChaincodeEvent){

	ce := <-ret_event
	handle_event_testing(ce)
}

func main() {
	//randsource := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	//r1 := mathrand.New(randsource)
	//fmt.Println(r1.Intn(100))
	//fmt.Println(r1.Intn(100))
	//return
	url :="http://127.0.0.1:7050/chaincode"
	eventAddress := "127.0.0.1:7053"
	numbers := flag.Int("s" , 10, "number of loops")

	flag.Parse()

	listenToRejections := false
	chaincodeID := NAME
	ret_event := make(chan *pbchain.Event_ChaincodeEvent)
	a := lib.CreateEventClient(eventAddress, listenToRejections, chaincodeID, "TESTING")
	go lib.ListenEvent(a, ret_event)
	//var retData RespData
	for i:=0;i<*numbers;i++ {
		create_test_blocks(url, "50", strconv.Itoa(i))
		handle_response(ret_event)
		time.Sleep(time.Second * 2)
		fmt.Println("finish the loop", i)
	}
	//if 1==2{
	//	query_test_blocks(url, strconv.Itoa(50*i))
	//	fmt.Println("press any to continue...")
	//	scanner2 := bufio.NewScanner(os.Stdin)
	//	scanner2.Scan()
	//	}
	//}
	fmt.Println("press any key to test query performance")
	scanner2 := bufio.NewScanner(os.Stdin)
		scanner2.Scan()
		query_test_blocks(url, strconv.Itoa(2000))
	return

	a = lib.CreateEventClient(eventAddress, listenToRejections, chaincodeID, "ADMIN")
	go lib.ListenEvent(a, ret_event)

	//_, retdata := upload_NG_for_voters(url)
	//
	//get_handle_result(ret_event, retdata)


	timenow := time.Now()
	privkey, _,retdata := upload_pubkey(url)
	get_handle_result(ret_event, retdata)
	timeTrack(timenow, "upload pubkey")


	timenow = time.Now()
	_, retdata = upload_tally_zero_pools(url,privkey)
	get_handle_result(ret_event, retdata)
	timeTrack(timenow, "upload zero pool")

	ring_param := Get_short_ring_params("outputWs.txt")
	timenow = time.Now()
	_, retdata =upload_ring_param(url, ring_param)
	get_handle_result(ret_event, retdata)
	timeTrack(timenow, "upload ring parameters")

	//var err error
	//a.Disconnected(err)


	fmt.Println("system prepartion done..")



	//mashed,_ := json.Marshal(privkey)
	//fmt.Println(base64.StdEncoding.EncodeToString(mashed))

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	fmt.Println("add it up")
	timenow = time.Now()
	retdata = add_vote(url)
	get_handle_result(ret_event, retdata)
	timeTrack(timenow, "add it up")


	ret, m,r := get_result(url,privkey)
	if ret == false{
		fmt.Println("error in get result")
		return
	}

	ret,retdata = upload_result_plaintext(url, m,r)

	if ret == false{
		fmt.Println("error in uploading plaintext")
		return
	}
	get_handle_result(ret_event, retdata)

	//for scanner.Scan() {
	//time.Sleep(time.Second*3)
	result := show_result(url,10)
	if result == nil{
		fmt.Println("get final result error!!")
		return
	}
	for i:=0;i<10;i++{
		fmt.Println(new(big.Int).SetBytes(result[i]))
	}
}
