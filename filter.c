
int typeCheck(node_t *ast) {
    int lhsType;
    int rhsType;
    int bin_id;
    int constant;

    if (ast->lhs == NULL && ast->rhs == NULL) {
        return ast->type;
    }
   
    if (ast->lhs == NULL || ast->rhs == NULL) {
        fprintf(stderr, "BUG: Error while typechecking - tree is not balanced\n");
        exit(1);
    }
    
    lhsType = typeCheck(ast->lhs);
    rhsType = typeCheck(ast->rhs);
    if (lhsType == TCONSTIP  || lhsType == TCONSTMAC ||
        lhsType == TCONSTDEC || lhsType == TCONSTHEX)
    {
        bin_id   = rhsType;
        constant = lhsType;
    }
    else if (rhsType == TCONSTIP  || rhsType == TCONSTMAC ||
             rhsType == TCONSTDEC || rhsType == TCONSTHEX)
    {
        bin_id   = lhsType;
        constant = rhsType;
    }
    else {
        return 0;
    }
    
    switch (bin_id) {
        case TIPSRC:
        case TIPDST:
        case TARPSIP:
        case TARPTIP:
            if (constant != TCONSTIP) {
                fprintf(stderr, "TypeCheck: Must specify an ip address\n");
                exit(1);
            }
            if (ast->type != TEQ && ast->type != TNE) {
                fprintf(stderr, "TypeCheck: IP address filtering can only be binary\n");
                exit(1);
            }
            return 0;
        case TETHSRC:
        case TETHDST:
        case TARPSHA:
        case TARPTHA:
            if (constant != TCONSTMAC) {
                fprintf(stderr, "TypeCheck: Must specify a mac address\n");
                exit(1);
            }
            if (ast->type != TEQ && ast->type != TNE) {
                fprintf(stderr, "TypeCheck: MAC address filtering can only be binary\n");
                exit(1);
            }
            return 0;
        case TTCPSRC:
        case TTCPDST:
        case TUDPSRC:
        case TUDPDST:
            if (constant != TCONSTDEC && constant != TCONSTHEX) {
                fprintf(stderr, "TypeCheck: Must specify an integer\n");
                exit(1);
            }
            return 0;
        default:
            return 0;
    }
}


uint32_t filter(node_t *ast, uint8_t *packet, uint8_t *res) {
    uint8_t lhsMac[6], rhsMac[6];
    uint32_t lhs, rhs;
    uint32_t value;

    switch (ast->type) {
    case TAND:
        return filter(ast->lhs, packet, NULL) && filter(ast->rhs, packet, NULL);
    case TOR:
        return filter(ast->lhs, packet, NULL) || filter(ast->rhs, packet, NULL);
    case TEQ:
        if (ast->lhs->type == TCONSTMAC || ast->rhs->type == TCONSTMAC) {
            filter(ast->lhs, packet, lhsMac);
            filter(ast->rhs, packet, rhsMac);
            return memcmp(lhsMac, rhsMac, 6) == 0;
        }
        if ((lhs = filter(ast->lhs, packet, NULL)) == 0 ||
            (rhs = filter(ast->rhs, packet, NULL)) == 0) {
            return 0;
        }
        return lhs == rhs;
    case TNE:
        if (ast->lhs->type == TCONSTMAC || ast->rhs->type == TCONSTMAC) {
            filter(ast->lhs, packet, lhsMac);
            filter(ast->rhs, packet, rhsMac);
            return memcmp(lhsMac, rhsMac, 6);
        }
        if ((lhs = filter(ast->lhs, packet, NULL)) == 0 ||
            (rhs = filter(ast->rhs, packet, NULL)) == 0) {
            return 0;
        }
        return lhs != rhs;
    case TLT:
        if ((lhs = filter(ast->lhs, packet, NULL)) == 0 ||
            (rhs = filter(ast->rhs, packet, NULL)) == 0) {
            return 0;
        }
        return lhs < rhs;
    case TLE:
        if ((lhs = filter(ast->lhs, packet, NULL)) == 0 ||
            (rhs = filter(ast->rhs, packet, NULL)) == 0) {
            return 0;
        }
        return lhs <= rhs;
    case TGT:
        if ((lhs = filter(ast->lhs, packet, NULL)) == 0 ||
            (rhs = filter(ast->rhs, packet, NULL)) == 0) {
            return 0;
        }
        return lhs > rhs;
    case TGE:
        if ((lhs = filter(ast->lhs, packet, NULL)) == 0 ||
            (rhs = filter(ast->rhs, packet, NULL)) == 0) {
            return 0;
        }
        return lhs >= rhs;
    case TCONSTIP:
        inet_pton(AF_INET, ast->attr, &value);
        return value;
    case TCONSTMAC:
        sscanf(ast->attr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", res, res + 1, res + 2,
               res + 3, res + 4, res + 5);
        return 0;
    case TCONSTDEC:
    case TCONSTHEX:
        return strtol(ast->attr, NULL, 0);
    case TETH:
        return 1;
    case TIP:
        return ((ethhdr *)packet)->h_proto == htons(ETH_P_IP);
    case TIP6:
        return ((ethhdr *)packet)->h_proto == htons(ETH_P_IPV6);
    case TICMP:
        if (((ethhdr *)packet)->h_proto == htons(ETH_P_IP)) {
            packet += sizeof(ethhdr);
            return ((iphdr *)packet)->protocol == IPPROTO_ICMP;
        }
        return 0;
    case TICMP6:
        if (((ethhdr *)packet)->h_proto == htons(ETH_P_IPV6)) {
            packet += sizeof(ethhdr);
            return ((ipv6hdr *)packet)->nexthdr == IPPROTO_ICMPV6;
        }
        return 0;
    case TTCP:
        if (((ethhdr *)packet)->h_proto == htons(ETH_P_IP)) {
            packet += sizeof(ethhdr);
            return ((iphdr *)packet)->protocol == IPPROTO_TCP;
        }
        return 0;
    case TUDP:
        if (((ethhdr *)packet)->h_proto != htons(ETH_P_IP)) {
            packet += sizeof(ethhdr);
            return ((iphdr *)packet)->protocol == IPPROTO_UDP;
        }
        return 0;
    case TTCPSYN:
    case TTCPACK:
    case TTCPPSH:
    case TTCPURG:
    case TTCPFIN:
    case TTCPRST:
    case TTCPCWR:
    case TTCPECE:
        if (((ethhdr *)packet)->h_proto == htons(ETH_P_IP)) {
            packet += sizeof(ethhdr);
            if (((iphdr *)packet)->protocol == IPPROTO_TCP)
                packet += sizeof(iphdr);
            else
                return 0;
        }
        else if (((ethhdr *)packet)->h_proto == htons(ETH_P_IPV6)) {
            packet += sizeof(ethhdr);
            if (((ipv6hdr *)packet)->nexthdr == IPPROTO_TCP)
                packet += sizeof(ipv6hdr);
            else
                return 0;
        }
        else {
            return 0;
        }

        switch (ast->type) {
            case TTCPSYN: return ((tcphdr *)packet)->syn;
            case TTCPACK: return ((tcphdr *)packet)->ack;
            case TTCPPSH: return ((tcphdr *)packet)->psh;
            case TTCPURG: return ((tcphdr *)packet)->urg;
            case TTCPFIN: return ((tcphdr *)packet)->fin;
            case TTCPRST: return ((tcphdr *)packet)->rst;
            case TTCPCWR: return ((tcphdr *)packet)->cwr;
            case TTCPECE: return ((tcphdr *)packet)->ece;
        }
    case TETHSRC:
        memcpy(res, ((ethhdr *)packet)->h_source, 6);
        return 0;
    case TETHDST:
        memcpy(res, ((ethhdr *)packet)->h_dest, 6);
        return 0;
    case TARPSHA:
        if (((ethhdr *)packet)->h_proto == htons(ETH_P_ARP)) {
            packet += sizeof(ethhdr);
            memcpy(res, ((arphdr *)packet)->ar_sha, 6);
        }
        else {
            memset(res, 0, 6);
        }
        return 0;
    case TARPTHA:
        if (((ethhdr *)packet)->h_proto == htons(ETH_P_ARP)) {
            packet += sizeof(ethhdr);
            memcpy(res, ((arphdr *)packet)->ar_tha, 6);
        }
        else {
            memset(res, 0, 6);
        }
        return 0;
    case TARPSIP:
        if (((ethhdr *)packet)->h_proto == htons(ETH_P_ARP)) {
            packet += sizeof(ethhdr);
            return *(((arphdr *)packet)->ar_sip);
        }
        return 0;
    case TARPTIP:
        if (((ethhdr *)packet)->h_proto == htons(ETH_P_ARP)) {
            packet += sizeof(ethhdr);
            return *(((arphdr *)packet)->ar_tip);
        }
        return 0;
    case TIPSRC:
        if (((ethhdr *)packet)->h_proto == htons(ETH_P_IP)) {
            packet += sizeof(ethhdr);
            return ((iphdr *)packet)->saddr;
        }
        return 0;
    case TIPDST:
        if (((ethhdr *)packet)->h_proto == htons(ETH_P_IP)) {
            packet += sizeof(ethhdr);
            return ((iphdr *)packet)->daddr;
        }
        return 0;
    case TTCPSRC:
    case TTCPDST:
        if (((ethhdr *)packet)->h_proto == htons(ETH_P_IP)) {
            packet += sizeof(ethhdr);
            if (((iphdr *)packet)->protocol == IPPROTO_TCP)
                packet += sizeof(iphdr);
            else
                return 0;
        }
        else if (((ethhdr *)packet)->h_proto == htons(ETH_P_IPV6)) {
            packet += sizeof(ethhdr);
            if (((ipv6hdr *)packet)->nexthdr == IPPROTO_TCP)
                packet += sizeof(ipv6hdr);
            else
                return 0;
        }
        else {
            return 0;
        }
        switch (ast->type) {
            case TTCPSRC:
                return ntohs(((tcphdr *)packet)->source);
            case TTCPDST:
                return ntohs(((tcphdr *)packet)->dest);
        }
    case TUDPSRC:
    case TUDPDST:
        if (((ethhdr *)packet)->h_proto == htons(ETH_P_IP)) {
            packet += sizeof(ethhdr);
            if (((iphdr *)packet)->protocol == IPPROTO_UDP)
                packet += sizeof(iphdr);
            else
                return 0;
        }
        else if (((ethhdr *)packet)->h_proto == htons(ETH_P_IPV6)) {
            packet += sizeof(ethhdr);
            if (((ipv6hdr *)packet)->nexthdr == IPPROTO_UDP)
                packet += sizeof(ipv6hdr);
            else
                return 0;
        }
        else {
            return 0;
        }
        switch (ast->type) {
            case TUDPSRC:
                return ntohs(((udphdr *)packet)->source);
            case TUDPDST:
                return ntohs(((udphdr *)packet)->dest);
        }
    }

    return 0;
}




