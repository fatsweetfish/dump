%option noyywrap
%{
#include <stdio.h>

#define TOK_COND        1
#define TOK_REL         2
#define TOK_BINARY_ID   3
#define TOK_UNARY_ID    4
#define TOK_CONST       5

int yylval;

typedef enum {
    TCONSTIP,
    TCONSTIP6,
    TCONSTMAC,
    TCONSTDEC,
    TCONSTHEX,

    TETH,
    TETHSRC,
    TETHDST,

    TARP,
    TARPSHA,
    TARPTHA,
    TARPSIP,
    TARPTIP,

    TIP,
    TIPSRC,
    TIPDST,

    TIP6,
    //TIP6SRC,
    //TIP6DST,

    TICMP,
    TICMP6,

    TTCP,
    TTCPSRC,
    TTCPDST,
    TTCPSYN,
    TTCPACK,
    TTCPPSH,
    TTCPURG,
    TTCPFIN,
    TTCPRST,
    TTCPCWR,
    TTCPECE,

    TUDP,
    TUDPSRC,
    TUDPDST,

    TLPAREN,
    TRPAREN,
    TEQ,
    TNE,
    TLT,
    TLE,
    TGT,
    TGE,
    TAND,
    TOR
} token_t;
%}

ip      ([0-9]{1,3}\.){3}[0-9]{1,3}
mac     ([a-fA-F0-9]{2}(\:|\-)){5}[a-fA-F0-9]{2}
dec     [0-9]+
hex     [0x[a-fA-F0-9]+

%%

[ \t\n] ;
{ip}            {yylval = TCONSTIP;  return TOK_CONST;}
{mac}           {yylval = TCONSTMAC; return TOK_CONST;}
{dec}           {yylval = TCONSTDEC; return TOK_CONST;}
{hex}           {yylval = TCONSTHEX; return TOK_CONST;}

"eth"           {yylval = TETH;    return TOK_UNARY_ID;}
"ip"            {yylval = TIP;     return TOK_UNARY_ID;}
"ipv6"          {yylval = TIP6;    return TOK_UNARY_ID;}
"icmp"          {yylval = TICMP;   return TOK_UNARY_ID;}
"icmpv6"        {yylval = TICMP6;  return TOK_UNARY_ID;}
"tcp"           {yylval = TTCP;    return TOK_UNARY_ID;}
"udp"           {yylval = TUDP;    return TOK_UNARY_ID;}
"tcp.flags.syn" {yylval = TTCPSYN; return TOK_UNARY_ID;}
"tcp.flags.ack" {yylval = TTCPACK; return TOK_UNARY_ID;}
"tcp.flags.psh" {yylval = TTCPPSH; return TOK_UNARY_ID;}
"tcp.flags.urg" {yylval = TTCPURG; return TOK_UNARY_ID;}
"tcp.flags.fin" {yylval = TTCPFIN; return TOK_UNARY_ID;}
"tcp.flags.rst" {yylval = TTCPRST; return TOK_UNARY_ID;}
"tcp.flags.cwr" {yylval = TTCPCWR; return TOK_UNARY_ID;}
"tcp.flags.ece" {yylval = TTCPECE; return TOK_UNARY_ID;}

"eth.src"       {yylval = TETHSRC; return TOK_BINARY_ID;}
"eth.dst"       {yylval = TETHDST; return TOK_BINARY_ID;}
"arp.sha"       {yylval = TARPSHA; return TOK_BINARY_ID;}
"arp.tha"       {yylval = TARPTHA; return TOK_BINARY_ID;}
"arp.sip"       {yylval = TARPSIP; return TOK_BINARY_ID;}
"arp.tip"       {yylval = TARPTIP; return TOK_BINARY_ID;}
"ip.src"        {yylval = TIPSRC;  return TOK_BINARY_ID;}
"ip.dst"        {yylval = TIPDST;  return TOK_BINARY_ID;}
"tcp.src"       {yylval = TTCPSRC; return TOK_BINARY_ID;}
"tcp.dst"       {yylval = TTCPDST; return TOK_BINARY_ID;}
"udp.src"       {yylval = TUDPSRC; return TOK_BINARY_ID;}
"udp.dst"       {yylval = TUDPDST; return TOK_BINARY_ID;}

"=="            {yylval = TEQ; return TOK_REL;}
"!="            {yylval = TNE; return TOK_REL;}
"<"             {yylval = TLT; return TOK_REL;}
"<="            {yylval = TLE; return TOK_REL;}
">"             {yylval = TGT; return TOK_REL;}
">="            {yylval = TGE; return TOK_REL;}

"&&"            {yylval = TAND; return TOK_COND;}
"||"            {yylval = TOR;  return TOK_COND;}

"("             {return TLPAREN;}
")"             {return TRPAREN;}

.           fprintf(stderr, "Unrecognized token in filter expression: \"%s\"\n", yytext); exit(1);

%%
