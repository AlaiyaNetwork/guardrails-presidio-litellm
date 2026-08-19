package main

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cloud-ru-tech/guardrails-llm-filter/pkg/guardrails/regex/registry"
	"github.com/cloud-ru-tech/guardrails-llm-filter/pkg/guardrails/regex/rule"
	"github.com/cloud-ru-tech/guardrails-llm-filter/pkg/guardrails/regex/scanners/sensitive"
)

const defaultAddr = ":5002"

type analyzeRequest struct {
	Text string `json:"text"`
	Language string `json:"language,omitempty"`
	Entities []string `json:"entities,omitempty"`
	ScoreThreshold *float64 `json:"score_threshold,omitempty"`
	AdHocRecognizers []json.RawMessage `json:"ad_hoc_recognizers,omitempty"`
	ReturnDecisionProcess bool `json:"return_decision_process,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
	Trace bool `json:"trace,omitempty"`
	Context []string `json:"context,omitempty"`
}

type analyzeResult struct { EntityType string `json:"entity_type"`; Start int `json:"start"`; End int `json:"end"`; Score float64 `json:"score"` }
type anonymizeRequest struct { Text string `json:"text"`; AnalyzerResults []analyzeResult `json:"analyzer_results"`; Anonymizers map[string]operatorConfig `json:"anonymizers,omitempty"` }
type operatorConfig struct { Type string `json:"type"`; NewValue string `json:"new_value,omitempty"`; CharsToMask int `json:"chars_to_mask,omitempty"`; MaskingChar string `json:"masking_char,omitempty"`; FromEnd bool `json:"from_end,omitempty"`; HashType string `json:"hash_type,omitempty"` }
type anonymizeItem struct { Start int `json:"start"`; End int `json:"end"`; EntityType string `json:"entity_type"`; Text string `json:"text"`; Operator string `json:"operator"` }
type anonymizeResponse struct { Text string `json:"text"`; Items []anonymizeItem `json:"items"` }
type engine struct { reg *registry.Registry; scanner *sensitive.Scanner; defaultIDs []string; byEntity map[string][]string; entityByID map[string]string }

func main() {
	eng, err := loadEngine(); if err != nil { slog.Error("failed to initialize guardrails engine", "error", err); os.Exit(1) }
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, map[string]any{"status":"ok"}) })
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, map[string]any{"status":"ok"}) })
	mux.HandleFunc("GET /supportedentities", eng.handleSupportedEntities)
	mux.HandleFunc("GET /recognizers", eng.handleRecognizers)
	mux.HandleFunc("GET /anonymizers", handleAnonymizers)
	mux.HandleFunc("GET /deanonymizers", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, []string{}) })
	mux.HandleFunc("POST /analyze", eng.handleAnalyze)
	mux.HandleFunc("POST /anonymize", handleAnonymize)
	addr := envOr("LISTEN_ADDR", defaultAddr)
	srv := &http.Server{Addr:addr, Handler:limitBody(mux,int64(envInt("MAX_BODY_BYTES",8<<20))), ReadHeaderTimeout:10*time.Second, IdleTimeout:60*time.Second}
	slog.Info("presidio-compatible guardrails service started", "addr", addr, "rules", len(eng.defaultIDs))
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err,http.ErrServerClosed) { slog.Error("server stopped","error",err); os.Exit(1) }
}

func loadEngine() (*engine,error) {
	paths := splitCSV(envOr("RULE_FILES","configs/guardrails_regex_rules.yaml,configs/guardrails_regex_rules.gitleaks.generated.yaml"))
	_, rules, err := rule.LoadAllFromFiles(paths...); if err != nil { return nil,err }
	enabled := make([]rule.Rule,0,len(rules)); for _,r := range rules { if r.DefaultOn || envBool("INCLUDE_DEFAULT_OFF",false) { enabled=append(enabled,r) } }
	if len(enabled)==0 { return nil,fmt.Errorf("no enabled rules loaded from %v",paths) }
	reg,err := registry.Build(enabled...); if err != nil { return nil,err }
	scanner := sensitive.New(reg,sensitive.WithKeywordPrefilter(envBool("KEYWORD_PREFILTER",true)))
	e := &engine{reg:reg,scanner:scanner,byEntity:make(map[string][]string),entityByID:make(map[string]string)}
	for _,r := range enabled { entity:=presidioEntity(r.Masking.Placeholder,r.Group); e.defaultIDs=append(e.defaultIDs,r.ID); e.byEntity[entity]=append(e.byEntity[entity],r.ID); e.entityByID[r.ID]=entity }
	sort.Strings(e.defaultIDs); for k:=range e.byEntity { sort.Strings(e.byEntity[k]) }; return e,nil
}

func (e *engine) handleSupportedEntities(w http.ResponseWriter,_ *http.Request){ entities:=make([]string,0,len(e.byEntity)); for entity:=range e.byEntity { entities=append(entities,entity) }; sort.Strings(entities); writeJSON(w,http.StatusOK,entities) }
func (e *engine) handleRecognizers(w http.ResponseWriter,_ *http.Request){ ids:=append([]string(nil),e.defaultIDs...); writeJSON(w,http.StatusOK,ids) }
func handleAnonymizers(w http.ResponseWriter,_ *http.Request){ writeJSON(w,http.StatusOK,[]string{"replace","redact","mask","hash"}) }

func (e *engine) handleAnalyze(w http.ResponseWriter,r *http.Request){
	var req analyzeRequest; if err:=decodeJSON(r,&req); err!=nil { writeError(w,http.StatusBadRequest,err); return }
	if strings.TrimSpace(req.Text)=="" { writeJSON(w,http.StatusOK,[]analyzeResult{}); return }
	ids:=e.defaultIDs; if len(req.Entities)>0 { ids=idsForEntities(req.Entities,e.byEntity) }; if len(ids)==0 { writeJSON(w,http.StatusOK,[]analyzeResult{}); return }
	matches,err:=e.scanner.Scan(req.Text,ids); if err!=nil { slog.Error("scan failed","error",err); writeError(w,http.StatusInternalServerError,errors.New("PII scan failed")); return }
	out:=make([]analyzeResult,0,len(matches)); threshold:=0.0; if req.ScoreThreshold!=nil { threshold=*req.ScoreThreshold }
	for _,m:=range matches { score:=1.0; if score<threshold { continue }; out=append(out,analyzeResult{EntityType:e.entityByID[m.RuleID],Start:byteToRuneOffset(req.Text,m.Start),End:byteToRuneOffset(req.Text,m.End),Score:score}) }
	writeJSON(w,http.StatusOK,out)
}

func handleAnonymize(w http.ResponseWriter,r *http.Request){
	var req anonymizeRequest; if err:=decodeJSON(r,&req); err!=nil { writeError(w,http.StatusBadRequest,err); return }
	if len(req.AnalyzerResults)==0 { writeJSON(w,http.StatusOK,anonymizeResponse{Text:req.Text,Items:[]anonymizeItem{}}); return }
	spans:=append([]analyzeResult(nil),req.AnalyzerResults...); sort.SliceStable(spans,func(i,j int)bool{ if spans[i].Start==spans[j].Start{return spans[i].End>spans[j].End}; return spans[i].Start<spans[j].Start })
	lastEnd:=0; for _,s:=range spans { if s.Start<0 || s.End<s.Start || s.Start<lastEnd || s.End>utf8.RuneCountInString(req.Text) { writeError(w,http.StatusBadRequest,errors.New("invalid or overlapping analyzer_results offsets")); return }; lastEnd=s.End }
	var b strings.Builder; items:=make([]anonymizeItem,0,len(spans)); prevRune:=0; outRunes:=0
	for _,s:=range spans { startByte:=runeToByteOffset(req.Text,s.Start); endByte:=runeToByteOffset(req.Text,s.End); prevByte:=runeToByteOffset(req.Text,prevRune); prefix:=req.Text[prevByte:startByte]; original:=req.Text[startByte:endByte]; replacement,operator,err:=applyOperator(original,s.EntityType,req.Anonymizers); if err!=nil { writeError(w,http.StatusUnprocessableEntity,err); return }; b.WriteString(prefix); itemStart:=outRunes+utf8.RuneCountInString(prefix); b.WriteString(replacement); itemEnd:=itemStart+utf8.RuneCountInString(replacement); items=append(items,anonymizeItem{Start:itemStart,End:itemEnd,EntityType:s.EntityType,Text:replacement,Operator:operator}); outRunes=itemEnd; prevRune=s.End }
	b.WriteString(req.Text[runeToByteOffset(req.Text,prevRune):]); writeJSON(w,http.StatusOK,anonymizeResponse{Text:b.String(),Items:items})
}

func idsForEntities(entities []string,byEntity map[string][]string)[]string{ seen:=make(map[string]struct{}); var ids []string; for _,raw:=range entities { entity:=strings.ToUpper(strings.TrimSpace(raw)); for _,id:=range byEntity[entity] { if _,ok:=seen[id];ok{continue}; seen[id]=struct{}{}; ids=append(ids,id) } }; sort.Strings(ids); return ids }
func presidioEntity(placeholder,group string)string{ p:=strings.ToUpper(strings.TrimSpace(placeholder)); switch p { case "EMAIL","EMAIL_ADDRESS":return "EMAIL_ADDRESS"; case "PHONE","PHONE_NUMBER","RU_PHONE":return "PHONE_NUMBER"; case "CARD","CREDIT_CARD","PAYMENT_CARD":return "CREDIT_CARD"; case "IPV4","IPV6","IP_ADDRESS":return "IP_ADDRESS"; case "PERSON","FULL_NAME","NAME":return "PERSON"; case "IBAN":return "IBAN_CODE" }; if p!=""{return p}; g:=strings.ToUpper(strings.TrimSpace(group)); if g!=""{return g}; return "SENSITIVE_DATA" }
func applyOperator(original,entity string,configs map[string]operatorConfig)(string,string,error){ cfg,ok:=configs[entity]; if !ok {cfg,ok=configs[strings.ToUpper(entity)]}; if !ok {cfg,ok=configs["DEFAULT"]}; if !ok || strings.TrimSpace(cfg.Type)=="" {return "<"+sanitizeEntity(entity)+">","replace",nil}; switch strings.ToLower(strings.TrimSpace(cfg.Type)){ case "replace": if cfg.NewValue!=""{return cfg.NewValue,"replace",nil}; return "<"+sanitizeEntity(entity)+">","replace",nil; case "redact":return "","redact",nil; case "mask": runes:=[]rune(original); n:=cfg.CharsToMask; if n<=0||n>len(runes){n=len(runes)}; maskRune:='*'; if cfg.MaskingChar!=""{maskRune,_=utf8.DecodeRuneInString(cfg.MaskingChar)}; if cfg.FromEnd {for i:=len(runes)-n;i<len(runes);i++{runes[i]=maskRune}} else {for i:=0;i<n;i++{runes[i]=maskRune}}; return string(runes),"mask",nil; case "hash": switch strings.ToLower(cfg.HashType){case "","sha256":sum:=sha256.Sum256([]byte(original)); return hex.EncodeToString(sum[:]),"hash",nil; case "sha512":sum:=sha512.Sum512([]byte(original)); return hex.EncodeToString(sum[:]),"hash",nil; default:return "","",fmt.Errorf("unsupported hash_type %q",cfg.HashType)}; default:return "","",fmt.Errorf("unsupported anonymizer operator %q",cfg.Type)} }
func sanitizeEntity(s string)string{ s=strings.ToUpper(strings.TrimSpace(s)); if s==""{return "SENSITIVE_DATA"}; var b strings.Builder; for _,r:=range s { if r>='A'&&r<='Z'||r>='0'&&r<='9'||r=='_' {b.WriteRune(r)} else {b.WriteByte('_')} }; return b.String() }
func byteToRuneOffset(s string,byteOffset int)int{ if byteOffset<=0{return 0}; if byteOffset>=len(s){return utf8.RuneCountInString(s)}; return utf8.RuneCountInString(s[:byteOffset]) }
func runeToByteOffset(s string,runeOffset int)int{ if runeOffset<=0{return 0}; n:=0; for i:=range s { if n==runeOffset{return i}; n++ }; return len(s) }
func decodeJSON(r *http.Request,dst any)error{ dec:=json.NewDecoder(r.Body); if err:=dec.Decode(dst);err!=nil{return fmt.Errorf("invalid JSON: %w",err)}; return nil }
func writeJSON(w http.ResponseWriter,status int,v any){ w.Header().Set("Content-Type","application/json"); w.WriteHeader(status); _=json.NewEncoder(w).Encode(v) }
func writeError(w http.ResponseWriter,status int,err error){ writeJSON(w,status,map[string]string{"error":err.Error()}) }
func limitBody(next http.Handler,n int64)http.Handler{ return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){ r.Body=http.MaxBytesReader(w,r.Body,n); next.ServeHTTP(w,r) }) }
func envOr(name,fallback string)string{ if v:=strings.TrimSpace(os.Getenv(name));v!=""{return v}; return fallback }
func envBool(name string,fallback bool)bool{ v:=strings.TrimSpace(os.Getenv(name)); if v==""{return fallback}; b,err:=strconv.ParseBool(v); if err!=nil{return fallback}; return b }
func envInt(name string,fallback int)int{ v:=strings.TrimSpace(os.Getenv(name)); if v==""{return fallback}; n,err:=strconv.Atoi(v); if err!=nil||n<=0{return fallback}; return n }
func splitCSV(v string)[]string{ parts:=strings.Split(v,","); out:=make([]string,0,len(parts)); for _,p:=range parts {if p=strings.TrimSpace(p);p!=""{out=append(out,p)}}; return out }
