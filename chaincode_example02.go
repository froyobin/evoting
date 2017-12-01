/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

//WARNING - this chaincode's ID is hard-coded in chaincode_example04 to illustrate one way of
//calling chaincode from a chaincode. If this example is modified, chaincode_example04.go has
//to be modified as well with the new ID of chaincode_example02.
//chaincode_example05 show's how chaincode ID can be passed in as a parameter instead of
//hard-coding.

import (
	"errors"
	"fmt"
	"strconv"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	//"github.com/hyperledger/fabric/examples/chaincode/go/pbc"
	"encoding/base64"
	//"github.com/satori/go.uuid"
	"encoding/json"
	"crypto/sha256"
	"github.com/op/go-logging"
	"github.com/roasbeef/go-go-gadget-paillier"
	mathrand "math/rand"
	"math/big"
	"time"
	"bytes"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"crypto"
	"log"
	"os"

)

var myLogger = logging.MustGetLogger("e-voting")

const (
	Base       = 2
	BC   = 32
	CHALLENGE_LENGTH = 80
	POOL_SIZE = 512
	KEYPOOL_SIZE = 512
	//notice offsetmax should be one smaill then the poosize
	OFFSETMAX = 12
	KEYOFFSETMAX = 511
	STAGE_END = 1
	STAGE_START = 0
	PL = 1360
	Mu = 3080
	ZERO_POOL_SIZE = 4096 //2^20
	PBC_MSG ="deadbeef"

)

type NG struct{
	N []byte
	G []byte
}


type BallotUpload struct{
	C []byte
	SigData SignedData
}


type ZgroupStruct struct{
	ZgroupVal []byte
	Positive int
}

type SignedData struct {
	UUID string
	HashC []byte
	As [][]byte
	//fixme we send the v here
	V []byte
	Piy []byte
	C []byte
	Zgroup []ZgroupStruct
}


type ShortRingPara struct {
	N []byte
	G []byte
	Hpi []byte
	Gpi []byte
}


// SimpleChaincode example simple Chaincode implementation
type SimpleChaincode struct {
	pubkeys string
	sharedParams string
	sharedG  [] byte
	privKey []byte
	pubkey []byte
	usermap map[string]user_info
	chainname string
	numcandidate int
	voterskeys voterpubkey
	TID uint64
	Poolindex int
	mk []*big.Int
	ballots map[string] *VoteMsg
	ballotpool BallotPool
	indicator BallotIndicator

	voterkeyindicator VoterKeyIndicator
	keyspool VoterkeyPool
	ringParam ShortRingPara
	stage int
	SmartcontractKey *rsa.PrivateKey
	zero_pool [][]byte
	voted_pool map[string]bool
	timecount *log.Logger
}


type RandomEpair struct {
	UUID string
	E_Vvalue []byte
}

type BallotIndicator struct{
	Blocks int
	Offset int
}

type VoterKeyIndicator struct {
	Blocks int
	Offset int
}


type ResultStruct struct{
	Result [][]byte
}

type BallotPool struct{
	Len int
	Ballots [POOL_SIZE][]byte
}

type VoterkeyPool struct{
	Len int
	Keys [KEYPOOL_SIZE]string
	Result []byte

}

type BallotPack struct{
	Ballot []byte
	Sig []byte
}



// PublicKey represents the public part of a Paillier key.
type PublicKey struct {
	N        []byte // modulus
	G        []byte // n+1, since p and q are same length
	NSquared []byte
}





type PrivkeyPart struct {
	L []byte
	U []byte
}


type VerifyData struct{
	E [][]byte
	V [][]byte
}

type VoteMsg struct {
	U [][]byte
	Check VerifyData
	E_c [] byte
	C []byte
	UUID string
}



type voting_auth_data struct {
    UUID    string
    A_val   string
	B_val   string
	SharedParams string
	SharedGBase64 string
	PubkeyBase64 string
}


type user_info struct
{
	UUID string
	Au string
	Bu string
	Private_s string
	Verified bool
	Auth_sign string
	Uesr_sign string
}

type Onblock_info struct{
	Auth_sign string
	Uesr_sign string
	Au string
	Bu string
}

type Cast struct{
	UUID string
	Au string
	Bu string
	Sighed_yt string
	Pubkey string
	S_val string
	E_val string
}

//func generate_params()(sharedParams string, sharedG []byte){
//    params := pbc.GenerateA(160, 512)
//    pairing := params.NewPairing()
//    g := pairing.NewG2().Rand()
//
//    sharedParams = params.String()
//    sharedG = g.Bytes()
//    return sharedParams,sharedG
//}

type Usersign struct{
	T string
	S []string
	C []string
}

type voterpubkey struct{
		Voterpubkey []string
		Num int
}



func Red(msg string)(string){
	return "\x1b[31;1m" + msg + "\x1b[0m"
}


func Blue(msg string)(string){
	return "\x1b[34;1m" + msg + "\x1b[0m"
}

func (t *SimpleChaincode)generate_candidates(L *big.Int, number int64)([]*big.Int){
		i := number
		candidate := make([]*big.Int, number,number)
		for i=0; i<number; i++{
			y := big.NewInt(2)
			y.Exp(L, big.NewInt(i), nil)

			candidate[i] = y
		}

	return candidate
}


var pubPEMData = []byte(`
-----BEGIN PUBLIC Privkey-----
MIICWwIBAAKBgQDPMd8LVfgnNZxxbohAMglNb8y5K3mRVg7/hlyCv+UAdtq/OKhG
b4Wv1LPnKyJV79Kn9nhrGbGJZiF7MVDUjRJbjfWIJDktxR2eI9g0R/qkPbCFxxjq
kVaF5ymfDpwLU7pDEDYBhhV2bUgW6sq4V8lIj0vWwPMPhJP+jEhxWNnuYwIDAQAB
AoGARZzo5oMc2/ecN1Q+vOrSy0yryO79akIyydFX1aopg61rM2ISz496qCfbxeht
Idhwu3QI41r/lj1VNHHOSYuYRcUzaFniwq6PTqEt/tzf4oobdGbbxaj0lVtTpjWk
lR/ZFK2SF53uUihWxfsjj7HocHBdP9DtE+ZrarJKYIuYGpkCQQDUByhGmUT8/iw+
bRLe2dReyQD+oaNvgWJo65utN+POL2R73d3GREGwVTlSjU+RBWecEMOkuFgoOiMe
LdK7yMtfAkEA+iodoIze02x6jVeBOYV0zURuKo4hEhxnhREbKhxIfShRkV7hd6RH
5vePFUlLFsakSUfif6K6NBLgiZZ3D6X/fQJAN6wJb0AfVS6H/3w0UD9x+9FbaYCX
oVeft1zl632ZWzImeD+xU7XoaZx3CK4CDloU8m2UcVPWEfnx7qKpipUWkQJAKL6H
SMjo2eKHK1IfN/EmjvAgSUoQ1NRPf/rDQ96LZ+cTMewUKNpW46VaZosjcbg0tcLB
fyxPy39vlrks9x2AOQJAC52o093YWGtTgmkjR/HsbNzEuvVGVut/sGewlD2FtHG8
8EYpt3l8ep+OImhXrZ2qAtBT2vHQX+epS9o+ek4hOg==
-----END PUBLIC Privkey-----
and some more`)


func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {
	t.chainname = args[0]
	number_can, err :=  strconv.Atoi(args[1])
	t.numcandidate = number_can
	if err != nil{
		myLogger.Debugf(Red("init failed"))
		return nil, err
	}
	t.Poolindex = 0
	t.mk = make([] *big.Int, number_can,number_can)
	L := new(big.Int).Exp(big.NewInt(Base), big.NewInt(BC), nil)
	for i:=0;i< number_can;i++ {
		t.mk[i] = new(big.Int).Exp(L,big.NewInt(int64(i)),nil)
	}


	t.indicator = BallotIndicator{0,0}
	t.indicator.Offset = OFFSETMAX

	t.voterkeyindicator = VoterKeyIndicator{0,0}
	t.voterkeyindicator.Offset = KEYOFFSETMAX

	t.stage = STAGE_START
	t.ballots = make(map[string]*VoteMsg)
	t.voted_pool = make(map[string]bool)
	myLogger.Debugf(Blue("init finished"))

	//load the smartcontract pem
	t32,_ := pem.Decode(pubPEMData)
	t.SmartcontractKey,_ = x509.ParsePKCS1PrivateKey(t32.Bytes)

	f, errfile := os.OpenFile("./testlogfile.log", os.O_RDWR | os.O_CREATE , 0666)
	if errfile != nil {
		fmt.Print("error opening file: %v", errfile)
	}
	defer f.Close()

	t.timecount = log.New(f, "",log.Ltime)

	return nil, nil
}




func (t* SimpleChaincode) calculate_vote(result []byte, num int, L *big.Int)([]*big.Int){
	retout := make([]*big.Int, num, num)
	totalnum := new(big.Int).SetBytes(result)

	for i:=0;i<num;i++{
		tmp := big.NewInt(1)
		tmp.Mod(totalnum, L)
		retout[i] = tmp
		totalnum.Rsh(totalnum, 32)
	}
	return retout
}


func (t* SimpleChaincode) get_result(stub shim.ChaincodeStubInterface,
		args[] string)([]byte, error){

	plaintext, _ := base64.StdEncoding.DecodeString(args[0])
	m := new(big.Int).SetBytes(plaintext)
	rplaintext, _ := base64.StdEncoding.DecodeString(args[1])
	r := new(big.Int).SetBytes(rplaintext)



	pubkeybase64, _ := stub.GetState("PUBKEY")
	pubkeyd, _ := base64.StdEncoding.DecodeString(string(pubkeybase64))
	var key_bytes PublicKey
	json.Unmarshal(pubkeyd, &key_bytes)
	pubKey := paillier.PublicKey{new(big.Int).SetBytes(key_bytes.N),
									  new(big.Int).SetBytes(key_bytes.G),
									  new(big.Int).SetBytes(key_bytes.NSquared)}
	c := new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(pubKey.G, m, pubKey.NSquared),
			new(big.Int).Exp(r, pubKey.N, pubKey.NSquared),
		),
		pubKey.NSquared,
	)

	org_cbyte,_ := stub.GetState("RESULT")
	org_c := new(big.Int).SetBytes(org_cbyte)


	if org_c.Cmp(c) == 0{
			myLogger.Debugf(Blue("Passed decryption check"))
	}else{
			myLogger.Debugf(Red("the plaintext donot match the ciphertext"))
			//stub.PutState("FINALRESULT", nil)
			return nil, errors.New("the plaintext and ciphertext doesnot match")
	}


	L := new(big.Int).Exp(big.NewInt(Base), big.NewInt(BC), nil)
	retout := t.calculate_vote(plaintext, t.numcandidate, L)


	var resultcontainer ResultStruct
	resultcontainer.Result = make([][]byte, t.numcandidate, t.numcandidate)
	for i:=0; i<t.numcandidate;i++{
		resultcontainer.Result[i] = retout[i].Bytes()
	}
	marshedjon,_ := json.Marshal(resultcontainer)
	stub.PutState("FINALRESULT", marshedjon)
	err := stub.SetEvent("ADMIN", []byte("UPLOAD PLAINTEXT SUCCESS"))
		if err != nil {
				return nil, errors.New("Failed to send event of upload  plaintext ")
		}
	return nil, nil

}


func (t *SimpleChaincode) create_test_blocks(
		stub shim.ChaincodeStubInterface, args[]string)([]byte, error){
			//fixme we set each ballot as 512Kb*2 and we test it with 512 ballot in one block
	var test_chunk [5120*2*512] byte
	test_chunk[0]='h'
	loop_times, _ := strconv.Atoi(args[0])
	base, _ := strconv.Atoi(args[1])
	for i:=0;i< loop_times;i++{
		val := base*loop_times+i
		msg := "TEST"+ strconv.Itoa(val)
		stub.PutState(msg, test_chunk[:])
		time.Sleep(time.Millisecond*30)
		//fmt.Println(val)
	}

	myLogger.Debugf(Blue("upload test successfully"))
	err := stub.SetEvent("TESTING", []byte("FINISH_UPLOADING_TEST_BLOCK"))
	if err != nil {
					return nil, errors.New("error to send event already voted")
					}

	return []byte("create test blocks successfully"),nil
}

func (t *SimpleChaincode) upload_Tally_pubkeys(
		stub shim.ChaincodeStubInterface, args[]string)([]byte, error){


	stub.PutState("PUBKEY", []byte(args[0]))
	myLogger.Debugf(Blue("upload pubkey successfully"))
	err := stub.SetEvent("ADMIN", []byte("PUBKEY SUCCESS"))
		if err != nil {
				return nil, errors.New("Failed to send event of upload pubkey")
		}

	return []byte("upload voters pubkeys successfully"),nil
}


func (t *SimpleChaincode) upload_Tally_NG(
		stub shim.ChaincodeStubInterface, args[]string)([]byte, error){

	stub.PutState("PUBKEY_NG",[]byte(args[0]))

	myLogger.Debugf(Blue("upload NG successfully"))
	err := stub.SetEvent("ADMIN", []byte("NG SUCCESS"))
		if err != nil {
				return nil, errors.New("Failed to send event of casting successfully")
		}
	return []byte("upload voters NG successfully"),nil
}


func (t *SimpleChaincode) verifyballot(stub shim.ChaincodeStubInterface,
		thisvote VoteMsg, pubkey paillier.PublicKey)(bool) {

	u := make([]*big.Int, t.numcandidate, t.numcandidate)
	elist := make([]*big.Int, t.numcandidate, t.numcandidate)
	v := make([]* big.Int, t.numcandidate, t.numcandidate)


	c := new(big.Int).SetBytes(thisvote.C)
	num := t.numcandidate




	sum_u := big.NewInt(0)
	for i := 0; i < t.numcandidate; i++ {
		u[i] = new(big.Int).SetBytes(thisvote.U[i])
		elist[i] = new(big.Int).SetBytes(thisvote.Check.E[i])
		v[i] = new(big.Int).SetBytes(thisvote.Check.V[i])
		sum_u.Add(sum_u, u[i])
	}

	h := sha256.New()
	// we want 80 bits, so we
	//h1 := h.Sum(nil)[:10]
	h1 := h.Sum(nil)
	hashval := new(big.Int).SetBytes(h1)
	e := new(big.Int).Mod(hashval, pubkey.N)


	total := big.NewInt(0)

	for i := 0; i < t.numcandidate;i++ {
		total.Add(total, elist[i])
	}
	if total.Mod(total, pubkey.N).Cmp(e) !=0{

		return false
	}

	m := t.mk
	var i int
	for i=0;i< num;i++ {
		left := new(big.Int).Exp(v[i], pubkey.N, pubkey.NSquared)
		gmj := new(big.Int).Exp(pubkey.G, m[i], pubkey.NSquared)
		right2 := new(big.Int).Mul(c,new(big.Int).ModInverse(gmj, pubkey.NSquared))

		right3 := right2.Exp(right2, elist[i], pubkey.NSquared)
		right := new(big.Int).Mul(right3, u[i])
		right.Mod(right,pubkey.NSquared)

		if left.Cmp(right) != 0{
			break
		}
	}
	if i != num{
		return false
	}
	return true
}

func (t *SimpleChaincode)create_putkey(
		stub shim.ChaincodeStubInterface, C string, indicator VoterKeyIndicator){
	var tmp VoterkeyPool
	tmp.Len = 1
	tmp.Keys[0] = C
	t.keyspool = tmp
	myLogger.Debugf(Blue("create a new pool and put a key in it"))

}


func (t *SimpleChaincode)create_put(stub shim.ChaincodeStubInterface, C []byte, indicator BallotIndicator){
	var tmp BallotPool
	tmp.Len = 1
	tmp.Ballots[0] = C
	t.ballotpool = tmp
	myLogger.Debugf(Blue("create a new pool and put a ballot in it"))

}


func (t *SimpleChaincode)put_key(stub shim.ChaincodeStubInterface, C string,
		indicator VoterKeyIndicator, state *bool){

	  defer func() {
        if r := recover(); r != nil {
            fmt.Println(Red("putting ballot in empty pool!"))
			t.voterkeyindicator.Offset -= 1
			*state = false
        }
    }()


	 t.keyspool.Keys[indicator.Offset] = C
	 t.keyspool.Len = t.keyspool.Len +1
	//updated, _ := json.Marshal(ballotpool)
	//stub.PutState(strconv.Itoa(indicator.Blocks), updated)
	msg := fmt.Sprintf("add a new key to key pool %d at offset %d", indicator.Blocks-1, indicator.Offset)
	myLogger.Debugf(Blue(msg))
	*state = true
}



func (t *SimpleChaincode)put_ballot(stub shim.ChaincodeStubInterface, C []byte,
		indicator BallotIndicator, state *bool){

	  defer func() {
        if r := recover(); r != nil {
			t.indicator.Offset -= 1
            fmt.Println(Red("putting ballot in empty pool!"))
			*state = false
        }
    }()


	t.ballotpool.Ballots[indicator.Offset] = C
	t.ballotpool.Len = t.ballotpool.Len +1
	//updated, _ := json.Marshal(ballotpool)
	//stub.PutState(strconv.Itoa(indicator.Blocks), updated)
	msg := fmt.Sprintf("add a new ballot to block pool %d at offset %d", indicator.Blocks-1, indicator.Offset)
	myLogger.Debugf(Blue(msg))
	*state = true
}


func (t *SimpleChaincode) Add_ballot(stub shim.ChaincodeStubInterface) {
	var indicator BallotIndicator
	indicator = t.indicator
	msg := fmt.Sprintf("the last block is %d, offset is %d", indicator.Blocks-1, indicator.Offset)
	myLogger.Debugf(Blue(msg))
	pubkeybase64, _ := stub.GetState("PUBKEY")
	pubkeyd, _ := base64.StdEncoding.DecodeString(string(pubkeybase64))
	var key_bytes PublicKey
	json.Unmarshal(pubkeyd, &key_bytes)

	pubkey := paillier.PublicKey{new(big.Int).SetBytes(key_bytes.N),
									  new(big.Int).SetBytes(key_bytes.G),
									  new(big.Int).SetBytes(key_bytes.NSquared)}

	result := t.zero_pool[0]
	for i:=0;i<indicator.Blocks;i++{
		var pool BallotPool
		//beforeadd := time.Now()
		marshed,_ := stub.GetState(t.chainname + strconv.Itoa(i))
		//elapsed := time.Since(beforeadd)
    	//t.timecount.Printf("%s took %s", "ADDBALLOT", elapsed)
		json.Unmarshal(marshed, &pool)
		for j := 0; j<pool.Len; j++{
			var uploadballot BallotUpload
			json.Unmarshal(pool.Ballots[j], &uploadballot)
			result = paillier.AddCipher(&pubkey, result, uploadballot.C)
		}
	}
	stub.PutState("RESULT", result)
}

func calculte_partv(stub shim.ChaincodeStubInterface, keyspool VoterkeyPool){

	v := big.NewInt(1)
	marshed,_ := stub.GetState("PUBKEY_NG")
	decoded,_ := base64.StdEncoding.DecodeString(string(marshed))

	var m NG
	json.Unmarshal(decoded, &m)
	keys := keyspool.Keys
	for i:=0;i< keyspool.Len;i++{
		decodedkey,_ := base64.StdEncoding.DecodeString(keys[i])
		y := new(big.Int).SetBytes(decodedkey)
		v.Mul(v, y)
	}
	keyspool.Result = v.Bytes()

}


func generate_Tpgroup(
		g,piy,C, V, gpi,hpi,N *big.Int, Zgroup, As ,
		Tp[]*big.Int){
		//defer timeTrack(time.Now(), "Tp group:")
	zero := big.NewInt(0)
	var part1, part2, tmp *big.Int
	//tmp = new(big.Int).Abs(Zgroup[6])
	tmp = new(big.Int).Exp(As[0], new(big.Int).Abs(Zgroup[6]), N)
	if Zgroup[6].Cmp(zero)<0 {
		tmp.ModInverse(tmp,N)

	}
	part1 = new(big.Int).Mod(
			new(big.Int).Mul(new(big.Int).Exp(V, C, N),tmp),
			N)

	part2 = new(big.Int).Exp(hpi, new(big.Int).Abs(Zgroup[3]), N)
	if Zgroup[3].Cmp(zero)>0 {

		part2.ModInverse(part2,N)

	}

	Tp[0] = new(big.Int).Mod(
		new(big.Int).Mul(part1,part2),
		N)


	A2c := new(big.Int).Exp(As[1], C, N)
	gza1 := new(big.Int).Exp(gpi, new(big.Int).Abs(Zgroup[0]), N)
	if Zgroup[0].Cmp(zero)<0{
		gza1.ModInverse(gza1, N)
	}
	gza2 := new(big.Int).Exp(hpi, new(big.Int).Abs(Zgroup[1]), N)
	if Zgroup[1].Cmp(zero)<0{
		gza2.ModInverse(gza2, N)
	}
	Tp[1] = new(big.Int).Mod(
		new(big.Int).Mul(A2c,new(big.Int).Mul(gza1,gza2)),N)



	A2Zy := new(big.Int).Exp(As[1], new(big.Int).Abs(Zgroup[6]), N)
	if Zgroup[6].Cmp(zero)>0 {
		A2Zy.ModInverse(A2Zy,N)

	}
	gzaf1 := new(big.Int).Exp(gpi, new(big.Int).Abs(Zgroup[3]),N)
	if Zgroup[3].Cmp(zero)<0{
		gzaf1.ModInverse(gzaf1, N)
	}
	gzaf2 := new(big.Int).Exp(hpi, new(big.Int).Abs(Zgroup[4]),N)
	if Zgroup[4].Cmp(zero)<0{
		gzaf2.ModInverse(gzaf2, N)
	}
	part1 = new(big.Int).Mul(gzaf1, gzaf2)
	Tp[2] = new(big.Int).Mod(
		new(big.Int).Mul(part1, A2Zy),N)



	halfL := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(PL/2)), N)
	gzp := new(big.Int).Exp(g, new(big.Int).Abs(Zgroup[7]), N)
	if Zgroup[7].Cmp(zero)<0{
		gzp.ModInverse(gzp, N)
	}
	g2l := new(big.Int).Exp(g, new(big.Int).Mul(halfL, C), N)
	g2l.ModInverse(g2l, N)
	gzp2l := new(big.Int).Mul(g2l, gzp)


	gzp2 := new(big.Int).Exp(g, new(big.Int).Abs(Zgroup[8]), N)
	if Zgroup[8].Cmp(zero)<0{
		gzp.ModInverse(gzp, N)
	}
	g2l2 := new(big.Int).Exp(g, new(big.Int).Mul(halfL, C), N)
	g2l2.ModInverse(g2l2, N)
	gzq2l := new(big.Int).Mul(g2l2, gzp2)

	part1 = new(big.Int).Mul(gzp2l, gzq2l)

	piyc := new(big.Int).Exp(piy, C, N)
	Tp[3] = new(big.Int).Mul(piyc, part1)
	Tp[3].Mod(Tp[3], N)


	gzp = new(big.Int).Exp(gpi, new(big.Int).Abs(Zgroup[7]), N)
	if Zgroup[7].Cmp(zero)<0{
		gzp.ModInverse(gzp, N)
	}
	g2l = new(big.Int).Exp(gpi, new(big.Int).Mul(halfL, C), N)
	g2l.ModInverse(g2l, N)
	gzp2l = new(big.Int).Mul(g2l, gzp)
	hza3 := new(big.Int).Exp(hpi, new(big.Int).Abs(Zgroup[2]), N)
	if Zgroup[2].Cmp(zero)<0{
		hza3.ModInverse(hza3, N)
	}
	A3c := new(big.Int).Exp(As[2], C, N)
	Tp[4] = new(big.Int).Mul(
		A3c, new(big.Int).Mul(hza3, gzp2l))
	Tp[4].Mod(Tp[4], N)



	gc := new(big.Int).Exp(gpi, C, N)
	A32 := new(big.Int).Exp(As[2], big.NewInt(2), N)
	gzp2 = new(big.Int).Exp(A32, new(big.Int).Abs(Zgroup[8]), N)

	if Zgroup[8].Cmp(zero)>0{
		gzp2.ModInverse(gzp2, N)
	}

	g2l2 = new(big.Int).Exp(A32, new(big.Int).Mul(halfL, C), N)
	out1 := new(big.Int).Mul(g2l2, gzp2)

	out1.Mul(out1,gc)

	gzy := new(big.Int).Exp(gpi, new(big.Int).Abs(Zgroup[6]), N)
	if Zgroup[6].Cmp(zero)<0{
		gzy.ModInverse(gzy, N)
	}
	hal3 := new(big.Int).Exp(hpi, new(big.Int).Abs(Zgroup[5]), N)
	if Zgroup[5].Cmp(zero)<0{
		hal3.ModInverse(hal3, N)
	}

	gzyhal3 := new(big.Int).Mul(gzy, hal3)
	out1.Mul(out1, gzyhal3)
	Tp[5] = new(big.Int).Mod(out1, N)

}




// Transaction makes payment of X units from A to B
func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {



	if function == "delete" {
		// Deletes an entity from its state
		return t.delete(stub, args)
	}

	//if function == "upload_sign" {
	//
	//	return t.upload_sign(stub, args)
	//}

	if function == "upload_tally_pubkey" {
		// upload tallying center pubkey
		if t.stage == STAGE_END{
			myLogger.Debugf(Red("end upload key stage!"))
			return nil, errors.New("cannot upload public key at this stage")
		}
		return t.upload_Tally_pubkeys(stub, args)
	}

	if function == "create_test_blocks"{
		myLogger.Debugf(Red("create test block"))
		return t.create_test_blocks(stub, args)
	}


	if function == "upload_tally_zero_pools"{
		if t.stage == STAGE_END{
			myLogger.Debugf(Red("end upload pool stage!"))
			return nil, errors.New("cannot upload zero pool at this stage")
		}
		decoded,_ := base64.StdEncoding.DecodeString(args[0])
		json.Unmarshal(decoded, &t.zero_pool)
		err := stub.SetEvent("ADMIN", []byte("ZERO POOL SUCCESS"))
		if err != nil {
				return nil, errors.New("Failed to send event of upload zero pools")
		}
		myLogger.Debugf(Blue("upload zero pool successfully"))
		return nil, nil
	}

	if function == "upload_NG" {
		// upload tallying center pubkey
		if t.stage == STAGE_END{
			myLogger.Debugf(Red("end upload key stage!"))
			return nil, errors.New("cannot upload public key at this stage")
		}
		return t.upload_Tally_NG(stub, args)
	}


	if function == "upload_Ring_Param" {
		// upload tallying center pubkey
		if t.stage == STAGE_END{
			myLogger.Debugf(Red("end upload key stage!"))
			return nil, errors.New("cannot upload public key at this stage")
		}
		stub.PutState("RING_PARAM",[]byte(args[0]))
		myLogger.Debugf(Blue("upload Ring Param successfully"))

		t1, _ := base64.StdEncoding.DecodeString(args[0])

		json.Unmarshal(t1, &t.ringParam)

		err := stub.SetEvent("ADMIN", []byte("RING PARAM SUCCESS"))
		if err != nil {
				return nil, errors.New("Failed to send event of upload ring parameters")
		}


		return []byte("upload voters Ring Param successfully"),nil

	}




	if function == "upload_voter_pubkey"{

		if t.voterkeyindicator.Offset == KEYOFFSETMAX{
		if t.voterkeyindicator.Blocks != 0{
			calculte_partv(stub,t.keyspool)
			jsonba, _ := json.Marshal(t.keyspool)
			stub.PutState(t.chainname +"KEYS"+ strconv.Itoa(t.voterkeyindicator.Blocks-1), jsonba)
			msg := fmt.Sprintf("we put the key pool %d on block", t.voterkeyindicator.Blocks-1)
			myLogger.Debugf(Blue(msg))
		}
		t.voterkeyindicator.Offset = 0
		t.voterkeyindicator.Blocks +=  1

		t.create_putkey(stub, args[0], t.voterkeyindicator)
		msg := fmt.Sprintf("we put the key %d on block with offset %d", t.voterkeyindicator.Blocks-1,t.voterkeyindicator.Offset)
		myLogger.Debugf(Blue(msg))
	}else{
		keystate := true
		for i:=0;i<4;i++ {
			//encrypt_zero,_ := paillier.Encrypt(&pubkey, big.NewInt(0).Bytes())
			//ret_add := paillier.AddCipher(&pubkey,thisvote.C, encrypt_zero)
			t.voterkeyindicator.Offset += 1

			t.put_key(stub, args[0], t.voterkeyindicator, &keystate)

			if keystate == true{
				break
			}
			time.Sleep(time.Millisecond*300)
		}
	}
	}

	if function == "upload_result_plaintext"{
		return t.get_result(stub,args)
	}


	if function == "Calculate_ballots"{

		t.stage = STAGE_END
		jsonba,_ := json.Marshal(t.ballotpool)
		alt := t.chainname + strconv.Itoa(t.indicator.Blocks-1)
		stub.PutState(alt, jsonba)
		myLogger.Debugf("we have updated last ballot pool on to chain")
		t.Add_ballot(stub)
		err := stub.SetEvent("ADMIN", []byte("ADDBALLOT SUCCESS"))
		if err != nil {
				return nil, errors.New("Failed to send event of upload pubkey")
		}
		return nil, nil
	}


	if function == "UPLOAD_U"{
		if t.stage == STAGE_END{
			myLogger.Debugf(Red("end upload key stage!"))
			return nil, errors.New("cannot upload public key at this stage")
		}

		marshed,_:= base64.StdEncoding.DecodeString(args[0])
		var thisvote VoteMsg
		json.Unmarshal(marshed, &thisvote)
		uuid := thisvote.UUID
		pubkeybase64, _ := stub.GetState("PUBKEY")
		pubkeyd, _ := base64.StdEncoding.DecodeString(string(pubkeybase64))
		var key_bytes PublicKey
		json.Unmarshal(pubkeyd, &key_bytes)

		pubkey := paillier.PublicKey{new(big.Int).SetBytes(key_bytes.N),
									  new(big.Int).SetBytes(key_bytes.G),
									  new(big.Int).SetBytes(key_bytes.NSquared)}
		vret := t.verifyballot(stub, thisvote, pubkey)
		if vret == false{
			myLogger.Debugf(Red("Error in check ballot"))
			return nil, errors.New("Error in check ballot")
		}

		h := sha256.New()
		h.Write([]byte(args[0]))
		hash_signed := h.Sum(nil)
		val := new(big.Int).SetBytes(hash_signed)
		pos := val.Mod(val,big.NewInt(POOL_SIZE))

		//encrypt_zero,_ := paillier.Encrypt(&pubkey, t.zero_pool[pos.Int64()])
		ret_add := paillier.AddCipher(&pubkey,thisvote.C, t.zero_pool[pos.Int64()])
		t.ballots[uuid] =&VoteMsg{thisvote.U, thisvote.Check,thisvote.E_c,
			ret_add, thisvote.UUID}

		myLogger.Debugf(Blue("uploaded the ballot"))

		return nil, nil
	}




	if function == "UPLOAD_RING_SIGN"{
		thisballot := t.ballots[args[0]]
		if thisballot == nil{
			return nil, errors.New("cannot find record of this uuid")
		}
		delete(t.ballots, args[0])

		marshed,_:= base64.StdEncoding.DecodeString(args[1])



		if len(marshed) == 0{
			return nil, errors.New("cannot find payload")
		}

		var signeddata SignedData
		json.Unmarshal(marshed, &signeddata)

		NS := new(big.Int).SetBytes(t.ringParam.N)
		gS := new(big.Int).SetBytes(t.ringParam.G)
		hpi := new(big.Int).SetBytes(t.ringParam.Hpi)
		gpi := new(big.Int).SetBytes(t.ringParam.Gpi)
		Tp := make([]*big.Int, 6, 6)
		piy := new(big.Int).SetBytes(signeddata.Piy)
		v := new(big.Int).SetBytes(signeddata.V)
		C := new(big.Int).SetBytes(signeddata.C)
		As := make([]*big.Int, 3, 3)

		_,exist := t.voted_pool[string(signeddata.Piy)]
		if exist{
			err := stub.SetEvent("VOTING", []byte("ALREADY_VOTED"))
			if err != nil {
					return nil, errors.New("error to send event already voted")
			}
			myLogger.Debugf(Red("this voter has already voted!"))
			return []byte("ALREADY_VOTED"), nil
		}else{
			t.voted_pool[string(signeddata.Piy)] = true
		}

		for i:=0;i<3;i++{
			As[i] = new(big.Int).SetBytes(signeddata.As[i])
		}

		Zgroup := make([]*big.Int, 9, 9)
		for i:=0;i<9;i++{
			Zgroup[i] = new(big.Int).SetBytes(signeddata.Zgroup[i].ZgroupVal)
			Zgroup[i].Mul(Zgroup[i], big.NewInt(int64(signeddata.Zgroup[i].Positive)))
		}


		generate_Tpgroup(gS, piy, C, v, gpi, hpi, NS, Zgroup, As, Tp)


		var byte_array2 []byte
		for i:=0;i<len(As);i++ {
			byte_array2 = append(byte_array2,signeddata.As[i]...)
		}

		for i:=0;i<len(Tp);i++ {
			byte_array2 = append(byte_array2, Tp[i].Bytes()...)
		}


		byte_array2 = append(byte_array2, v.Bytes()...)
		byte_array2 = append(byte_array2, thisballot.C...)

		h2 := sha256.New()
		//h1 := h.Sum(nil)[:10]
		h2.Write(byte_array2)
		hash_signed2 := h2.Sum(nil)
		//fmt.Println(signeddata.HashC)
		//fmt.Println(hash_signed2)
		if bytes.Equal(signeddata.HashC, hash_signed2)==false{

			myLogger.Debugf(Red("error in short ring signature check"))
			return nil, errors.New("error in short ring signature")
		}

		myLogger.Debugf(Blue("accept the ballot"))

		var indicator BallotIndicator
		in, _ := stub.GetState("INDICATOR")
		//pool_marshed,_ := stub.GetState(strconv.Itoa(indicator.Blocks))
		json.Unmarshal(in, &indicator)

		var uploadballot BallotUpload
		uploadballot.C = thisballot.C
		uploadballot.SigData = signeddata
		updata,_ := json.Marshal(uploadballot)
		msgt := fmt.Sprintf("we put the size %d", len(updata))
		myLogger.Debugf(Blue(msgt))
		if t.indicator.Offset == OFFSETMAX{
			if t.indicator.Blocks != 0{
				jsonba, _ := json.Marshal(t.ballotpool)
				stub.PutState(t.chainname + strconv.Itoa(t.indicator.Blocks-1), jsonba)
				msg := fmt.Sprintf("we put the pool %d on block", t.indicator.Blocks-1)

				myLogger.Debugf(Blue(msg))
			}
			t.indicator.Offset = 0
			t.indicator.Blocks +=  1


			t.create_put(stub, updata, t.indicator)
			msg := fmt.Sprintf("we put the pool %d on block with offset %d", t.indicator.Blocks-1,t.indicator.Offset)
			myLogger.Debugf(Blue(msg))
		}else{
			state := true
			for i:=0;i<4;i++ {

				//encrypt_zero,_ := paillier.Encrypt(&pubkey, big.NewInt(0).Bytes())
				//ret_add := paillier.AddCipher(&pubkey,thisvote.C, encrypt_zero)
				t.indicator.Offset += 1
				t.put_ballot(stub, updata, t.indicator, &state)

				if state == true{
					break
				}
				time.Sleep(time.Millisecond*300)
			}
		}
		err := stub.SetEvent("VOTING", []byte("CAST SUCCESS"))
		if err != nil {
				return nil, errors.New("Failed to send event of casting successfully")
		}
		return nil,nil
	}

	return []byte("hello"), nil
	var A, B string    // Entities
	var Aval, Bval int // Asset holdings
	var X int          // Transaction value
	var err error

	if len(args) != 3 {
		return nil, errors.New("Incorrect number of arguments. Expecting 3")
	}

	A = args[0]
	B = args[1]

	// Get the state from the ledger
	// TODO: will be nice to have a GetAllState call to ledger
	Avalbytes, err := stub.GetState(A)
	if err != nil {
		return nil, errors.New("Failed to get state")
	}
	if Avalbytes == nil {
		return nil, errors.New("Entity not found")
	}
	Aval, _ = strconv.Atoi(string(Avalbytes))

	Bvalbytes, err := stub.GetState(B)
	if err != nil {
		return nil, errors.New("Failed to get state")
	}
	if Bvalbytes == nil {
		return nil, errors.New("Entity not found")
	}
	Bval, _ = strconv.Atoi(string(Bvalbytes))

	// Perform the execution
	X, err = strconv.Atoi(args[2])
	if err != nil {
		return nil, errors.New("Invalid transaction amount, expecting a integer value")
	}
	Aval = Aval - X
	Bval = Bval + X
	fmt.Printf("Aval = %d, Bval = %d\n", Aval, Bval)

	// Write the state back to the ledger
	err = stub.PutState(A, []byte(strconv.Itoa(Aval)))
	if err != nil {
		return nil, err
	}

	err = stub.PutState(B, []byte(strconv.Itoa(Bval)))
	if err != nil {
		return nil, err
	}

	return nil, nil
}

// Deletes an entity from state
func (t *SimpleChaincode) delete(stub shim.ChaincodeStubInterface, args []string) ([]byte, error) {
	if len(args) != 1 {
		return nil, errors.New("Incorrect number of arguments. Expecting 1")
	}

	A := args[0]

	// Delete the key from the state in ledger
	err := stub.DelState(A)
	if err != nil {
		return nil, errors.New("Failed to delete state")
	}

	return nil, nil
}

//func (t *SimpleChaincode) sign_au_bu(this_user user_info)(string){
//	Au := this_user.Au
//	Bu := this_user.Bu
//	msg := Au + Bu
//	pairing, _ := pbc.NewPairingFromString(t.sharedParams)
//	h := pairing.NewG1().SetFromStringHash(msg, sha256.New())
//	privKey := pairing.NewZr().SetBytes(t.privKey)
//	signature := pairing.NewG2().PowZn(h, privKey)
//	return base64.StdEncoding.EncodeToString(signature.Bytes())
//
//}

func (t *SimpleChaincode)query_v(stub shim.ChaincodeStubInterface)([]byte){
	var m VoterkeyPool
	y := big.NewInt(1)
	for i:=0;i<t.voterkeyindicator.Blocks;i++{
		result,_ := stub.GetState(t.chainname +"KEYS"+ strconv.Itoa(i))
		json.Unmarshal(result, &m)
		y.Mul(y, new(big.Int).SetBytes(m.Result))
	}
	// we have also calculte that is not saved on blocks and put it on block
	y1 := big.NewInt(1)
	for i:=0;i<t.keyspool.Len;i++{
		decodedkey,_ := base64.StdEncoding.DecodeString(t.keyspool.Keys[i])
		y1.Mul(y1, new(big.Int).SetBytes(decodedkey))
	}
	t.keyspool.Result = y1.Bytes()
	jsonba, _ := json.Marshal(t.keyspool)
	stub.PutState(t.chainname +"KEYS"+ strconv.Itoa(t.voterkeyindicator.Blocks), jsonba)


	return y.Bytes()
}



// Query callback representing the query of a chaincode
func (t *SimpleChaincode) Query(stub shim.ChaincodeStubInterface, function string, args []string) ([]byte, error) {


	if function == "query_pubkey"{

		dat, err := stub.GetState("PUBKEY")
		if err != nil{
			return nil, err
		}else{
			return []byte(dat), nil
		}

	}

	if function == "query_test"{
		myLogger.Debugf(Red("in query test"))
		randsource := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
		r1 := mathrand.New(randsource)
		boundary,_ := strconv.Atoi(args[0])
		myLogger.Debugf(Red("in query test"))
		var pos [50]int
		for i:=0;i<50;i++{
			pos[i] = r1.Intn(boundary)

		}
		timenow := time.Now()
		for i:=0;i<50;i++{
			msg := "TEST"+ strconv.Itoa(pos[i])
			stub.GetState(msg)
		}
		elapsed := time.Since(timenow)
		fmt.Println("takes %s", elapsed)
		return nil,nil
	}


	if function == "query_v"{
		v := t.query_v(stub)
		//fmt.Println(v)
		return v, nil
	}


	if function == "query_smartcontract_key"{
		PubASN1, err := x509.MarshalPKIXPublicKey(&t.SmartcontractKey.PublicKey)
		if err != nil {
			myLogger.Debugf(Red("error in fetching public key"))
		}
		pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: PubASN1,
		})

		encoded := base64.StdEncoding.EncodeToString(pubBytes)
		return []byte(encoded), nil

	}

	if function == "Get_Vote"{
		sendbase64 := ""
		defer func(){
			if err:=recover();err!=nil{
				myLogger.Debugf(Red("vote has not been found yet"))
			}
		}()

		marshedjon,_ := json.Marshal(t.ballots[args[0]])
		//fmt.Println(new(big.Int).SetBytes(t.ballots[args[0]].C))
		base64marshedjon := base64.StdEncoding.EncodeToString(marshedjon)
		hashed := sha256.Sum256(t.ballots[args[0]].C)
		signature, err := rsa.SignPKCS1v15(rand.Reader, t.SmartcontractKey, crypto.SHA256, hashed[:])
		if err != nil {
			myLogger.Debugf(Red("Error in signature creation"))
        	return nil, nil
		}

		ballot := BallotPack{[]byte(base64marshedjon), signature}

		marshedjon,_ = json.Marshal(ballot)

		sendbase64 = base64.StdEncoding.EncodeToString(marshedjon)
		//sendbase64 := base64.StdEncoding.EncodeToString(marshedjon)
		return []byte(sendbase64), nil
	}




	if function == "query_NG"{

		NG, err := stub.GetState("PUBKEY_NG")
		if err != nil{
			return nil, err
		}else{
			return NG, nil
		}

	}

	if function == "query_Ring_Param"{

		ret, err := stub.GetState("RING_PARAM")
		if err != nil{
			return nil, err
		}else{
			return ret, nil
		}

	}



	if function == "get_result" {
		result,_ := stub.GetState("RESULT")
		result_base := base64.StdEncoding.EncodeToString(result)
		return []byte(result_base), nil
	}



	if function == "show_result"{
		ret,err := stub.GetState("FINALRESULT")
		if (ret==nil|| err != nil){
			return []byte(nil), errors.New("empty result")
		}
		return []byte(base64.StdEncoding.EncodeToString(ret)), nil
	}

	return []byte("wrong"), nil
}

func main() {
	MyChaincode := new(SimpleChaincode)
	MyChaincode.pubkeys = "abc"
	err := shim.Start(MyChaincode)
	if err != nil {
		fmt.Printf("Error starting Simple chaincode: %s", err)
	}
}
