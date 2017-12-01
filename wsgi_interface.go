package main

import (
	"github.com/go-martini/martini"
	"fmt"
	"net/http"
	"io/ioutil"
)


func InitVoting(req *http.Request){
	fmt.Println(req.FormValue("candidate"))
	val,_ := ioutil.ReadAll(req.Body)
	fmt.Println(string(val))
}

func main() {
	m := martini.Classic()
	//m.Post("/admin/:operation", func(params martini.Params) string {
  	//	return "Hello " + params["operation"]
	//
	//})

	m.Group("/admin", func(r martini.Router) {
		r.Post("/init", InitVoting)
	//	//r.Post("/tally", NewBook),
	//	//r.Put("/update/:id", UpdateBook)
	//	//r.Delete("/delete/:id", DeleteBook)
	})

	//m.Post("/attributes/:resource", binding.Json( attribute{} ), addAttribute  )



  m.Run()
}
