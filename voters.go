package main

import (
	"fmt"
	"encoding/json"
	"net/http"
	"bytes"
	"io/ioutil"
	"encoding/base64"
	"crypto/sha256"
	//"math/big"
	"github.com/roasbeef/go-go-gadget-paillier"
	"crypto/rand"
	"math/big"
	"github.com/satori/go.uuid"
	"gopkg.in/cheggaaa/pb.v1"
	"time"
	"io"
	"bufio"
	"os"
	"crypto"
	mathrand "math/rand"
	"encoding/pem"
	"crypto/rsa"
	"crypto/x509"
	"lib"
	pbchain "github.com/hyperledger/fabric/protos"
	"sync"
	"log"
)

var Eventflag int
var m *sync.Mutex
const (
	NAME       = "00584dcdd9d14b29958e78088bbb9a24c1cab4e11387732c33b327d4c6fecc2fca73ad2b6fa447e3511fc468b0e9b2cac4e0256962dc31e2d47fc2a82aaf70ef"
	Base       = 2
	BC   = 32
	PK = 256
	PL = 1360
	Mu = 3080
	VOTED = 2
	NOMATCH = 0
	SUCCESS = 1
	IGNORE  =3
)
type Voterkeys struct {
	X []byte
	Y []byte
}


type PrivkeyByte struct{
	Pub []byte
	Q []byte
	P []byte
}

type Pbc_KEY struct{
	Privkey []byte
	Pubkey []byte
}


type VoteMsg struct {
	U [][]byte
	C []byte
	E []byte
	UUID string
	Check VerifyData
}

type BallotPack struct{
	Ballot []byte
	Sig []byte
}


type ShortRingPara struct {
	N []byte
	G []byte
	Hpi []byte
	Gpi []byte
}



type voterskey struct {
	P *big.Int
	Q *big.Int
	Y *big.Int
}

// PublicKey represents the public part of a Paillier key.
type PublicKey struct {
	N        []byte // modulus
	G        []byte // n+1, since p and q are same length
	NSquared []byte
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

type Message struct {
    Name string
    Body string
	abs string
    Time int64
}

type JsonData struct {
	Jsonrpc string
	Method string
	Params Params
	Id string
}

type Params struct {
	Type int
	ChaincodeId ChainID
	CtorMsg CtorMsg
	SecureContext string
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

type NG struct{
	N []byte
	G []byte
}


type voting_auth_data struct {
    UUID    string
    A_val   string
	B_val   string
	SharedParams string
	SharedGBase64 string
	PubkeyBase64 string
}


type ResultStruct struct{
	status string
	message interface{}
}

type RespStruct struct {
	Jsonrpc string
	Result interface{}
	Id string
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

type Usersign struct{
	T string
	S []string
	C []string
}

type VerifyData struct{
	E [][]byte
	V [][]byte
}


func fetch_smartcontract_key(url string)(RespData){

	ChainIDSend := ChainID{NAME}
	//args := [] string{"b"}
	CtorMsgSend := CtorMsg{"query_smartcontract_key", nil}
	//CtorMsgSend := CtorMsg{"query", args}
	ParamsSend := Params{1, ChainIDSend, CtorMsgSend,"jim" }
	jsend := JsonData{"2.0", "query", ParamsSend,"5"}
	b, err := json.Marshal(jsend)
	//var jsonStr = []byte(`{"title":"Buy cheese and bread for breakfast."}`)
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
	status := resp.Status
	ret := RespData{body,status}
	return ret
}




func fetch_Ring_param(url string)(RespData){

	ChainIDSend := ChainID{NAME}
	//args := [] string{"b"}
	CtorMsgSend := CtorMsg{"query_Ring_Param", nil}
	//CtorMsgSend := CtorMsg{"query", args}
	ParamsSend := Params{1, ChainIDSend, CtorMsgSend,"jim" }
	jsend := JsonData{"2.0", "query", ParamsSend,"5"}
	b, err := json.Marshal(jsend)
	//var jsonStr = []byte(`{"title":"Buy cheese and bread for breakfast."}`)
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
	status := resp.Status
	ret := RespData{body,status}
	return ret
}


func fetch_pubkey(url string)(RespData){

	ChainIDSend := ChainID{NAME}
	//args := [] string{"b"}
	CtorMsgSend := CtorMsg{"query_pubkey", nil}
	//CtorMsgSend := CtorMsg{"query", args}
	ParamsSend := Params{1, ChainIDSend, CtorMsgSend,"jim" }
	jsend := JsonData{"2.0", "query", ParamsSend,"5"}
	b, err := json.Marshal(jsend)
	//var jsonStr = []byte(`{"title":"Buy cheese and bread for breakfast."}`)
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
	status := resp.Status
	ret := RespData{body,status}
	return ret
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
		//fmt.Println("call remote successfully")
		return true, ret
	}else{
		return false, ret
	}

}


type Voter struct {
	r []byte
	rou *big.Int
	e []*big.Int
	Key *paillier.PublicKey
}


func (ct *Voter)gen_u(num, picked int, key *paillier.PublicKey,
		L *big.Int)([]*big.Int,[] *big.Int, []byte){

	vjn := big.NewInt(1)
	gmj_quo := big.NewInt(1)

	p_r, _ := rand.Int(rand.Reader, key.N)
	ct.rou = p_r
	u := make([] *big.Int, num,num)
	m := make([] *big.Int, num,num)
	v := make([] *big.Int, num,num)
	ct.e = make([] *big.Int, 10,10)
	e := ct.e

	for i:=0;i< num;i++ {
		m[i] = new(big.Int).Exp(L,big.NewInt(int64(i)),nil)
		v[i],_ = rand.Int(rand.Reader, key.N)
		e[i],_ = rand.Int(rand.Reader, key.N)
	}

	c, r, _ := paillier.Encrypt(key, m[picked].Bytes())
	ct.r  = r
	for i:=0;i< num;i++{
		if i == picked{
			u[i] = new(big.Int).Exp(p_r, key.N, key.NSquared)
			continue
		}
		vjn = vjn.Exp(v[i], key.N, key.NSquared)
		gmj := new(big.Int).Exp(key.G, m[i], key.NSquared)
		quo := new(big.Int).Mul(
			gmj,new(big.Int).ModInverse(new(big.Int).SetBytes(c), key.NSquared))
		gmj_quo = gmj_quo.Exp(quo, e[i], key.NSquared)
		u[i] = new(big.Int).Mul(vjn, gmj_quo)
		u[i].Mod(u[i], key.NSquared)
	}

	return u,v,c
}

func (ct *Voter) update_v(v []*big.Int, e *big.Int, picked int){
	sum_e := big.NewInt(0)
	ct.e[picked] = big.NewInt(0)
	for i:=0;i<len(ct.e);i++{
		sum_e.Add(sum_e, ct.e[i])
	}
	local_e := big.NewInt(1)
	local_e.Mul(local_e, e)
	sub := new(big.Int).Sub(local_e, sum_e)
	ct.e[picked] = new(big.Int).Mod(sub, ct.Key.N)
	ei := new(big.Int).Mod(sub,ct.Key.N)
	//fixme try to add 1 to ei so the check will fail
	//ei.Add(ei, big.NewInt(1))
	left1 := ct.rou.Mul(ct.rou, new(big.Int).Exp(new(big.Int).SetBytes(ct.r), ei, ct.Key.N))
	left1.Mod(left1, ct.Key.NSquared)
	C4 := big.NewInt(0)
	if sub.Cmp(big.NewInt(0)) == -1{
		C4 = new(big.Int).ModInverse(ct.Key.G, ct.Key.NSquared)
	}else{
		C4 = ct.Key.G
	}
	//FIXME  instend of using sub/N I use N/sub as sub is small then N
	quota := new(big.Int).Quo(sub.Abs(sub), ct.Key.N)
	//fmt.Println("bbbbbccc" , quota)
	out := new(big.Int).Exp(C4, quota, ct.Key.NSquared)
	v1 := new(big.Int).Mul(left1, out)
	v1.Mod(v1, ct.Key.NSquared)
	v[picked] = v1

}


func generate_u( c1 *Voter, number_can, candidate_id int,
		pubkey *paillier.PublicKey, L *big.Int)([]*big.Int,[] *big.Int, []byte){
	c1.Key = pubkey
	c1.rou = big.NewInt(0)
	u,v,c := c1.gen_u(number_can,candidate_id, pubkey, L)
	return u, v, c
}

func decode_message(data []byte)(string){
	var m RespStruct
	json.Unmarshal(data, &m)
	msg := m.Result
	ret := msg.(map[string]interface{})
	msgEncoded := ret["message"].(string)
	return msgEncoded
}

func generate_rand(N *big.Int)(*big.Int){
	randsource := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	r  := new(big.Int).Rand(randsource, N)
	return r
}

func generateA(
		key *voterskey,As,a []*big.Int,W,N,hpi,gpi *big.Int)(error){
	//two := big.NewInt(2)

	for i:=0;i<3;i++ {
		a[i] = generate_rand(N)
	}

	//tmp1 := generate_rand(N)
	//tmp2 := generate_rand(N)
	//gpi = gpi.Exp(tmp1, two, N)
	//hpi = hpi.Exp(tmp2,two,N)
	//fixme we use the first user as the signer
	As[0] = new(big.Int).Mul(W, new(big.Int).Exp(hpi, a[0], N))
	As[0].Mod(As[0],N)
	tmpgp := new(big.Int).Exp(gpi, a[0],N)
	tmphp := new(big.Int).Exp(hpi, a[1], N)
	As[1] = new(big.Int).Mul(tmpgp, tmphp)
	As[1] = new(big.Int).Mod(As[1],N)
	As[2] = new(big.Int).Mul(new(big.Int).Exp(gpi, key.P,N),new(big.Int).Exp(hpi, a[2],N))
	As[2].Mod(As[2], N)
	return nil
}


func generate_groupparams(agroup, alphagroup, pqgroup []*big.Int, alphay *big.Int, N *big.Int){
		//defer timeTrack(time.Now(), "calculate G group")
	for i:= 0;i<3;i++{
		agroup[i] = generate_rand(N)
		alphagroup[i] = generate_rand(N)
	}
	alphay = alphay.Add(generate_rand(N), big.NewInt(0))
	range_n := new(big.Int).Exp(big.NewInt(2), big.NewInt(PK+Mu),nil)
	//fmt.Println(range_n)
	//return
	for i :=0;i<2;i++{
		pqgroup[i] = generate_rand(range_n)
		pqgroup[i].Mod(pqgroup[i], N)
	}
	return
}


func generate_Tgroup(Tgroup, A, agroup, alphagroup,pqgroup []*big.Int,N,g, gpi,hpi,
alphay *big.Int){
	//defer timeTrack(time.Now(), "Tgroup")

	var part1 *big.Int
	var part2 *big.Int

	Tgroup[0] = new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(A[0], alphay, N),
			new(big.Int).ModInverse(new(big.Int).Exp(hpi, alphagroup[0], N),N)),
		N,
	)


	Tgroup[1] = new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(gpi, agroup[0], N),
			new(big.Int).Exp(hpi, agroup[1], N),
		),
		N,
	)


	part1 = new(big.Int).ModInverse(new(big.Int).Exp(A[1], alphay,N),N)
	part2 = new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(gpi, alphagroup[0], N),
			new(big.Int).Exp(hpi, alphagroup[1], N),
		),
		N,
	)

	Tgroup[2] = new(big.Int).Mod(
		new(big.Int).Mul(
			part1,
			part2,
		),
		N,
	)



	Tgroup[3] = new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(g, pqgroup[0], N),
			new(big.Int).Exp(g, pqgroup[1], N),
		),
		N,
	)


	Tgroup[4] = new(big.Int).Mod(
			new(big.Int).Mul(
				new(big.Int).Exp(gpi, pqgroup[0], N),
				new(big.Int).Exp(hpi, agroup[2], N),
			),
			N,
		)


	A32 := new(big.Int).Exp(A[2], big.NewInt(2), N)
	part1 = new(big.Int).ModInverse(new(big.Int).Exp(A32, pqgroup[1],N),N)

	part2 = new(big.Int).Mod(
		new(big.Int).Mul(
			new(big.Int).Exp(gpi, alphay, N),
			new(big.Int).Exp(hpi, alphagroup[2], N),
		),
		N,
	)

	Tgroup[5] = new(big.Int).Mod(
		new(big.Int).Mul(part1,part2),
		N)


	return
}

func generate_Zgroup(Tgroup, A,Aa, agroup, alphagroup,pqgroup []*big.Int,N,alphay,
V*big.Int, MSG []byte, key *voterskey, c *big.Int)([]*big.Int) {
		//defer timeTrack(time.Now(), "Z group")
	var totalbyte []byte
	for i:=0;i<len(A);i++{
		tmp := A[i].Bytes()
		totalbyte = append(totalbyte, tmp...)
	}
	for i:=0;i<len(Tgroup);i++{
		tmp := Tgroup[i].Bytes()
		totalbyte = append(totalbyte, tmp...)
	}
	totalbyte = append(totalbyte, V.Bytes()...)
	totalbyte = append(totalbyte, MSG...)
	h := sha256.New()
	//h1 := h.Sum(nil)[:10]
	h.Write(totalbyte)
	h1 := h.Sum(nil)
	c = c.Mod(new(big.Int).SetBytes(h1), N)
	Zgroup := make([]*big.Int, 9, 9)

	for i:=0;i<3;i++ {
		Zgroup[i] = new(big.Int).Sub(agroup[i], new(big.Int).Mul(c, Aa[i]))
	}

	Zgroup[3] =
	new(big.Int).Sub(alphagroup[0], new(big.Int).Mul(c,new(big.Int).Mul(Aa[0], key.Y)))

	Zgroup[4] =
	new(big.Int).Sub(
		alphagroup[1], new(big.Int).Mul(
			c,new(big.Int).Mul(Aa[1], key.Y)))


	Zgroup[5] =
			new(big.Int).Sub(alphagroup[2], new(big.Int).Mul(
			c,new(big.Int).Mul(new(big.Int).Mul(Aa[2],big.NewInt(2)), key.Q)))

	Zgroup[6] = new(big.Int).Sub(alphay, new(big.Int).Mul(c,key.Y))

	halfL := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(PL/2)), N)

	phalfL := new(big.Int).Sub(key.P, halfL)
	qhalfL := new(big.Int).Sub(key.Q, halfL)

	cphalfL := new(big.Int).Mul(c, phalfL)
	cqhalfL := new(big.Int).Mul(c, qhalfL)

	Zgroup[7] = new(big.Int).Sub(pqgroup[0],cphalfL)
	Zgroup[8] = new(big.Int).Sub(pqgroup[1],cqhalfL)

	return Zgroup

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

	//return part1

	//tmp = new(big.Int).Exp(As[0], new(big.Int).Abs(Zgroup[3]), N)
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




func sign_on_vote(vote VoteMsg, key *voterskey, Ws, N,g,hpi,gpi *big.Int)(string){
	v := big.NewInt(0)
	v.Exp(Ws, key.Y, N)
	Aa := make([]*big.Int,3,3)
	As := make([]*big.Int, 3, 3)

	generateA(key, As, Aa, Ws, N,hpi,gpi)

	agroup := make([]*big.Int, 3, 3)
	alphagroup := make([]*big.Int, 3, 3)
	alphay := big.NewInt(0)
	pqgroup := make([]*big.Int, 2, 2)
	generate_groupparams(agroup, alphagroup, pqgroup, alphay, N)
	Tgroup := make([]*big.Int, 6, 6)
	generate_Tgroup(Tgroup, As, agroup, alphagroup, pqgroup, N, g, gpi, hpi, alphay)

	C := big.NewInt(0)

	Zgroup := generate_Zgroup(
		Tgroup, As, Aa, agroup, alphagroup, pqgroup, N, alphay, v, vote.C, key, C)

	//fixme we create piy here
	piy := new(big.Int).Exp(g, new(big.Int).Add(key.P, key.Q), N)


	var byte_array []byte
	for i:=0;i<len(As);i++ {
		byte_array = append(byte_array,As[i].Bytes()...)
	}

	for i:=0;i<len(Tgroup);i++ {
		byte_array = append(byte_array,Tgroup[i].Bytes()...)
	}


	byte_array = append(byte_array, v.Bytes()...)
	byte_array = append(byte_array, vote.C...)

	h := sha256.New()
	h.Write(byte_array)
	hash_signed := h.Sum(nil)
	var Zgroupbyte  []ZgroupStruct
	var Asbyte [][]byte
	for i:=0;i<len(Zgroup);i++{
		var tmp ZgroupStruct
		tmp.ZgroupVal = Zgroup[i].Bytes()
		tmp.Positive = Zgroup[i].Sign()
		Zgroupbyte= append(Zgroupbyte, tmp)
	}
	for i:=0;i<len(As);i++{
		Asbyte = append(Asbyte, As[i].Bytes())
	}

	data := SignedData{vote.UUID, hash_signed, Asbyte,
		v.Bytes(), piy.Bytes(), C.Bytes(),Zgroupbyte}
	jsdata,_ := json.Marshal(data)
	base64string := base64.StdEncoding.EncodeToString(jsdata)
	//fmt.Println(hash_signed)
	return base64string

}




func cast_my_vote(url string, candidate_id, number_can int,
		key *voterskey, Ws *big.Int)(bool,RespData) {
	var retData RespData
	resp := fetch_pubkey(url)
	c1 := new(Voter)
	key_msg := decode_message(resp.Body)
	t1, _ := base64.StdEncoding.DecodeString(key_msg)
	var key_bytes PublicKey
	json.Unmarshal(t1, &key_bytes)

	TallyingKey := paillier.PublicKey{new(big.Int).SetBytes(key_bytes.N),
									  new(big.Int).SetBytes(key_bytes.G),
									  new(big.Int).SetBytes(key_bytes.NSquared)}


	resp = fetch_smartcontract_key(url)
	key_msg = decode_message(resp.Body)
	pubBytes, _ := base64.StdEncoding.DecodeString(key_msg)
	t2,_ := pem.Decode(pubBytes)
	ppkey,_ := x509.ParsePKIXPublicKey(t2.Bytes)
	smartcontractpubkey := ppkey.(*rsa.PublicKey)

	resp = fetch_Ring_param(url)
	key_msg = decode_message(resp.Body)
	t1, _ = base64.StdEncoding.DecodeString(key_msg)
	var NGpack ShortRingPara
	json.Unmarshal(t1, &NGpack)
	NS := new(big.Int).SetBytes(NGpack.N)
	gS := new(big.Int).SetBytes(NGpack.G)
	hpi := new(big.Int).SetBytes(NGpack.Hpi)
	gpi := new(big.Int).SetBytes(NGpack.Gpi)


	L := new(big.Int).Exp(big.NewInt(Base), big.NewInt(BC), nil)

	u, v, c := generate_u(c1, number_can, candidate_id, &TallyingKey, L)
	var myvotemsg VoteMsg
	myvotemsg.U = make([][]byte, number_can, number_can)

	for i := 0; i < number_can; i++ {
		myvotemsg.U[i] = u[i].Bytes()
	}
	myvotemsg.UUID = fmt.Sprintf("%s", uuid.NewV4())
	myvotemsg.C = c

	sum_u := big.NewInt(0)
	for i:=0;i< number_can; i++{
		sum_u.Add(sum_u, u[i])
	}
	h := sha256.New()
	//h1 := h.Sum(nil)[:10]
	h1 := h.Sum(nil)
	hashval := new(big.Int).SetBytes(h1)
	e := new(big.Int).Mod(hashval, TallyingKey.N)

	c1.update_v(v,e,candidate_id)
	//FIXME this is test that we add a error in the V array
	//v[8].Add(v[8], big.NewInt(1))
	//var UpverifyData VerifyData
	myvotemsg.Check.E = make([][]byte, number_can, number_can)
	myvotemsg.Check.V = make([][]byte, number_can, number_can)
	for i := 0; i < number_can; i++ {
		myvotemsg.Check.E[i] = c1.e[i].Bytes()
		myvotemsg.Check.V[i] = v[i].Bytes()
	}
	marshupload, _ := json.Marshal(myvotemsg)
	upload_base64 := base64.StdEncoding.EncodeToString(marshupload)
	args := [] string{upload_base64}
	retupload, _ := upload(url, "UPLOAD_U", "invoke", args)
	if retupload == false {
		fmt.Println("upload E and V failed")
		return false, retData
	}
	//we get the vote from smart contract and then add the short ring signature
	var vote VoteMsg
	var sign []byte

	for true {
		vote, sign = fetch_vote(url, myvotemsg.UUID)
		if (len(vote.C)) != 0 {
			break
		}else{
			time.Sleep(time.Millisecond*20)
		}
	}

	hashed := sha256.Sum256(vote.C)
	retsig := rsa.VerifyPKCS1v15(smartcontractpubkey, crypto.SHA256, hashed[:], sign)
	if retsig != nil{
		fmt.Println(retsig)
		return false, retData
	}
	signedmsg := sign_on_vote(vote, key, Ws,NS,gS,hpi,gpi)
	args = [] string{myvotemsg.UUID, signedmsg}
	retupload, retData = upload(url, "UPLOAD_RING_SIGN", "invoke", args)
	if retupload == false {
		fmt.Println("creating signature failed")
		return false, retData
	}

	return true, retData

}

//
//func GenerateKey(random io.Reader, bits int) (*voterskey, error) {
//	one := big.NewInt(1)
//	two := big.NewInt(2)
//	pubkey := big.NewInt(1)
//	p := big.NewInt(1)
//	q := big.NewInt(1)
//	for true {
//		p, err := rand.Prime(random, bits/2)
//		if err != nil {
//			return nil, err
//		}
//
//		q, err := rand.Prime(random, bits/2)
//		if err != nil {
//			return nil, err
//		}
//		pp := new(big.Int).Mul(two, p)
//		pubkey = new(big.Int).Add(one,new(big.Int).Mul(q, pp))
//		if pubkey.ProbablyPrime(10)== true{
//			break
//		}
//
//	}
//
//	key := voterskey{p, q, pubkey}
//		return &key,nil
//	}
//


func fetch_vote(url,uuid string)(VoteMsg,[]byte) {
	var vote VoteMsg
	var ballot BallotPack
	ChainIDSend := ChainID{NAME}
	args := [] string{uuid}
	CtorMsgSend := CtorMsg{"Get_Vote", args}
	ParamsSend := Params{1, ChainIDSend, CtorMsgSend, "jim" }
	jsend := JsonData{"2.0", "query", ParamsSend, "5"}
	b, err := json.Marshal(jsend)
	//var jsonStr = []byte(`{"title":"Buy cheese and bread for breakfast."}`)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(b))
	req.Header.Set("X-Custom-Header", "Linux")
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}


	defer resp.Body.Close()

	defer func(){
		if err:=recover();err!=nil{
			vote.C = []byte("")
			ballot.Sig = []byte("")
		}
	}()



	body, _ := ioutil.ReadAll(resp.Body)
	status := resp.Status

	key_msg := decode_message(body)
	t1, _ := base64.StdEncoding.DecodeString(key_msg)
	json.Unmarshal(t1, &ballot)


	encodedVote,_ := base64.StdEncoding.DecodeString(string(ballot.Ballot))

	json.Unmarshal(encodedVote, &vote)
	//
	if status != "200 OK" {
		return vote, []byte("")
	}

	return vote, ballot.Sig
}


func upload_voter_keys(url string, keys []*voterskey, barkey *pb.ProgressBar)(ret bool){
	for i:=0;i<len(keys);i++ {
		pubkey := keys[i].Y
		//dpubkey, _ := json.Marshal(pubkey)
		bstring := base64.StdEncoding.EncodeToString(pubkey.Bytes())
		args := [] string{bstring}
		ret, _ := upload(url, "upload_voter_pubkey", "invoke", args)
		if ret ==false{
			return ret
		}
		barkey.Increment()
	}
		return  true

}


func check(e error) {
    if e != nil {
        panic(e)
    }
}

func Get_Ws_N_g(filename string,Ws []*big.Int, num int ){

	fi, err := os.Open(filename)
	check(err)
	 defer func() {
        if err := fi.Close(); err != nil {
            panic(err)
        }
    }()
	r := bufio.NewReader(fi)

	for i:=2; i<num+2;i++ {
		// read a chunk
		line, err := r.ReadBytes('\n')
		if err != nil && err != io.EOF {
			panic(err)
		}
		if len(line) == 0 {
			break
		}
		var m []byte
		json.Unmarshal(line, &m)
		Ws[i-2] = new(big.Int).SetBytes(m)
	}


}


func get_key_from_file(filename string,
		keys []*voterskey, NUM int)( bool){
	fi, err := os.Open(filename)
	check(err)
	 defer func() {
        if err := fi.Close(); err != nil {
            panic(err)
        }
    }()
	r := bufio.NewReader(fi)


    for i:=0; i<NUM;i++ {
		// read a chunk
		line, err := r.ReadBytes('\n')
		if err != nil && err != io.EOF {
			panic(err)
		}

		if len(line) == 0 {
			break
		}

		var m PrivkeyByte
		json.Unmarshal(line, &m)
		keys[i] = &voterskey{
			new(big.Int).SetBytes(m.P),new(big.Int).SetBytes(m.Q),
			new(big.Int).SetBytes(m.Pub)}


	}
	return true

}

func Red(msg string)(string){
	return "\x1b[31;1m" + msg + "\x1b[0m"
}


func handle_event(ce *pbchain.Event_ChaincodeEvent,retData RespData)(int){

	var m RespStruct
	retval := NOMATCH
	json.Unmarshal(retData.Body, &m)
	msg := m.Result
	ret := msg.(map[string]interface{})
	tid := ret["message"].(string)
	//if ce.ChaincodeEvent.EventName != "VOTING"{
	//		fmt.Println("ignore.......")
	//		return IGNORE
	//}
	if tid == ce.ChaincodeEvent.TxID{
	testval := string(ce.ChaincodeEvent.Payload)
	switch (testval) {
	case "ALREADY_VOTED":
		retval = VOTED
	case "CAST SUCCESS":
		retval = SUCCESS
	}
	}else{
		return NOMATCH
	}
	return retval
}

func timeTrack(timelog *log.Logger ,start time.Time, name string) {
    elapsed := time.Since(start)
    timelog.Printf("%s took %s", name, elapsed)
}

func main() {
	url :="http://dockland:7050/chaincode"
	number_can := 10
	num := 10
	eventAddress := "dockland:7053"
	listenToRejections := false
	chaincodeID := NAME

	f, errfile := os.OpenFile("testlogfile", os.O_RDWR | os.O_CREATE , 0666)
	if errfile != nil {
		fmt.Print("error opening file: %v", errfile)
	}
	defer f.Close()

	timecount := log.New(f, "",log.Ltime)

	ret_event := make(chan *pbchain.Event_ChaincodeEvent)

	a := lib.CreateEventClient(eventAddress, listenToRejections, chaincodeID,"VOTING")
	go lib.ListenEvent(a, ret_event)
	if a == nil {
		fmt.Printf("Error creating event client\n")
		return
	}

	mapvote := make(map[int]int64)
	b := make([]byte, num)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("error:", err)
		return
	}



	Ws := make([]*big.Int, num,num)

	Get_Ws_N_g("/home/yb/tools/outputWs.txt",Ws, num)

	voter_keys := make([]*voterskey, num, num)

	ret_get_key := get_key_from_file("/home/yb/tools/output.txt", voter_keys, len(voter_keys))
	//fmt.Println(voter_pbc_key[2])
	if ret_get_key == false{
		return
	}

	for i:=0;i<num;i++{
		b[i] = b[i]%byte(number_can)
		mapvote[int(b[i])]++
	}
	time.Sleep(time.Microsecond*100)
	//barkey.FinishPrint("upload the keys finished press any key to continue voting...")
	//scanner := bufio.NewScanner(os.Stdin)
	//scanner.Scan()
	//cast the vote stage
	bar := pb.StartNew(num).Prefix("uploadint the votes:")

	for i:=0;i<num; i++ {
		candidate_id := int(b[i])
		timenow := time.Now()
		ret,retData := cast_my_vote(url, candidate_id, number_can,
			voter_keys[i], Ws[i])
		timeTrack(timecount, timenow,"casting")
		if ret == false {
			fmt.Println("error!!")
			return
		}
		//time.Sleep(time.Millisecond*50)
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
			case IGNORE:
				leaveloop = true
				break
			default:
				leaveloop = true
				break
			}
			if leaveloop{
				break
			}
		}

		bar.Increment()
	}

	for i:=5;i<6; i++ {
		candidate_id := int(b[i])
		ret,retData := cast_my_vote(url, candidate_id, number_can, voter_keys[i], Ws[i])
		if ret == false {
			fmt.Println("error!!")
			return
		}
		//time.Sleep(time.Millisecond*50)


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
			case IGNORE:
				leaveloop = true
				break
			default:
				leaveloop = true
				break
			}
			if leaveloop{
				break
			}
		}

		bar.Increment()
	}


	for j:=0;j<number_can;j++{
		outstr := fmt.Sprintf("%d", mapvote[j])
		bar.FinishPrint(outstr)
	}
	bar.FinishPrint("The End!")
}
