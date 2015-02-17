
typedef struct node_t {
    token_t type;
    void *attr;
    struct node_t *lhs;
    struct node_t *rhs;
} node_t;

node_t * expr();
node_t * cond_rest(node_t *lhs);
node_t * cond();
node_t * rel();
node_t * term(int type);

void error()
{
    if (yyleng == 1) {
        fprintf(stderr, "Invalid filter expression. Expected more input.\n");
    }
    else {
        fprintf(stderr, "Unexpected token \"%s\"\n", yytext);
    }
    exit(1);
}


node_t * parse()
{
    return expr();
}


node_t * expr()
{
    return cond();
}


node_t * cond_rest(node_t *lhs)    // Eliminate left recursion
{
    int tok;
    node_t *node = (node_t *) malloc(sizeof(node_t));
    
    tok = yylex();
    if (tok == TOK_COND) {
        node->type = yylval;
        node->lhs  = lhs;
        node->rhs  = rel();
        return cond_rest(node);
    }
    else if (tok == 0) {
        free(node);
        return lhs;
    }
    else {
        error();
    }
}
   

node_t * cond()
{
    return cond_rest(rel());
}


node_t * rel()
{
    int tok;
    node_t *node = (node_t *) malloc(sizeof(node_t));

    tok = yylex();
    switch (tok) {
    case TOK_CONST:
    case TOK_BINARY_ID:
        node->lhs = term(tok);
        if ((tok = yylex()) != TOK_REL) {
            error();
        }
        node->type = yylval;
        node->rhs = term(yylex());
        return node;
    case TOK_UNARY_ID:
        node->type = yylval;
        node->lhs  = NULL;
        node->rhs  = NULL;
        node->attr = NULL;
        return node;
    case TLPAREN:
        free(node);
        node = cond();
        if (yylex() != TLPAREN) {
            fprintf(stderr, "Expected closing ')'\n");
            error();
        }
        return node;
    default:
        error();
    }
}


node_t * term(int type)
{
    node_t *node = (node_t *) malloc(sizeof(node_t));

    node->type = yylval;
    node->lhs  = NULL;
    node->rhs  = NULL;

    if (type == TOK_CONST) {
        node->attr = (char *) malloc(yyleng + 1);
        strncpy((char *)node->attr, yytext, yyleng);
        ((char *)node->attr)[yyleng] = 0;
    }
    else if (type == TOK_BINARY_ID) {
        node->attr = NULL;
    }
    else {
        error();
    }

    return node;
}
