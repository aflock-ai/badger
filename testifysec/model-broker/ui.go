package broker

import (
	"html/template"
	"net/http"
)

// A small connection-test page for people, at / on the internal listener.
var page = template.Must(template.New("broker").Parse(`<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Badger Broker</title>
<style>{{.Theme}}
main{max-width:56rem}label{display:block;margin:var(--sp-4) 0 var(--sp-1);font-weight:600}textarea{width:100%;min-height:10rem}#chat button{margin:var(--sp-4) 0}</style>
<main class="page"><div class="eyebrow">Badger broker</div><h1>Model connection test</h1><p class="muted">{{.Principal}}</p>
<p class="notice {{if .Configured}}is-ok{{else}}is-warning{{end}}">{{if .Configured}}Credentials configured. Use the test below to verify inference.{{else}}Waiting for a model key. Model requests are disabled.{{end}}</p>
<ul>{{range .Targets}}<li>{{.Model}}: {{.Host}}{{if not .Configured}} (no key){{end}}</li>{{end}}</ul>
<form id="chat"><label for="model">Model</label><select id="model">{{range .Targets}}<option value="{{.Model}}">{{.Model}}</option>{{end}}</select><label for="prompt">Test prompt (synthetic data only)</label><textarea id="prompt" maxlength="8000">Reply with a short greeting.</textarea><button class="btn-primary" {{if not .Configured}}disabled{{end}}>Test model</button></form><pre id="result" aria-live="polite">No model request made.</pre></main>
<script>document.querySelector('#chat').addEventListener('submit',async(e)=>{e.preventDefault();const b=e.target.querySelector('button');b.disabled=true;const o=document.querySelector('#result');o.textContent='Waiting for the model...';try{const r=await fetch('./v1/chat/completions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({model:document.querySelector('#model').value,messages:[{role:'user',content:document.querySelector('#prompt').value}],max_completion_tokens:256,stream:false})});const j=await r.json();o.textContent=r.ok?(j.choices?.[0]?.message?.content||JSON.stringify(j,null,2)):'Request failed (HTTP '+r.status+').';}catch{o.textContent='Request failed. Check the connection.';}finally{b.disabled=false;}});</script></html>`))

type target struct {
	Model      string
	Host       string
	Configured bool
}

func showPage(w http.ResponseWriter, principal string, routes []*RouteConfig) {
	targets := make([]target, 0, len(routes))
	configured := len(routes) > 0
	for _, r := range routes {
		t := target{Model: r.Model, Host: r.target.Host, Configured: secret(r.KeyFile) != ""}
		configured = configured && t.Configured
		targets = append(targets, t)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	_ = page.Execute(w, struct {
		Theme      template.CSS
		Principal  string
		Configured bool
		Targets    []target
	}{template.CSS(themeCSS), principal, configured, targets})
}
