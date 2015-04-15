/**
 * Protocoale de comunicatie -- Tema 4 2014
 * @author	Mardaloescu Serban, 334CA
 */
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dns_message.h"

#define MAXBUF  4096
#define DOMSIZE  256
#define DNSPORT 53
#define TIMEOUT 2

/**
 * Procedura care cere de la un server DNS informatii despre un domeniu.
 * Intoarce informatiile in message, iar adresa ip a serverului in server_ip.
 * Returneaza 1 in caz de eroare si 0 in rest.
 */
int request_info(const char *domain,
                 const char *type,
                 char       *message,
                 char       *server_ip)
{

    int sockfd;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return 1;
    }

    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(sockfd, &read_fds);

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port   = htons(DNSPORT);
    int flag = -1;
		FILE* msg = fopen("message.log", "a");
		
    while (1) {
        if (get_new_dns_server(server_ip) != 0) {
            fprintf(stderr,
                    "No available DNS server.\n");
            return 1;
        }

        inet_aton(server_ip, &server.sin_addr);

        if (sendto(sockfd, message, set_header(message) + set_question(message, domain, type), 0, (struct sockaddr *) &server,
                   sizeof(struct sockaddr_in)) < 0)
        {
            return 1;
        }
				
        fd_set tmp = read_fds;
        struct timeval timeout = {TIMEOUT, 0};
        
        int sel;
        if ((sel = select(sockfd + 1, &tmp, NULL, NULL, &timeout)) <= 0) {
        		flag = 1;
            continue;
        }
        flag = 0;
        if(!flag) {
        	int i;
        	for(i = 0; i < 512; i++) {
        		fprintf(msg, "%02X ", message[i] - '\0');
        	}
        	fprintf(msg, "\n");
        }
        int rec;
        if ((rec = recvfrom(sockfd, message, MAXBUF, 0, NULL, NULL)) <= 0) {
            return 1;
        }

        get_new_dns_server(NULL);
        break;
    }

    close(sockfd);

    return 0;
}

/**
 * Functie apelata de print_rr.  Se ocupa de NS.
 */
void print_rr_ns(FILE       *log,
                 const char *domain,
                 const char *message,
                 int         offset)
{
    char name[DOMSIZE];
    qname_to_domain(name, message, offset + sizeof(struct dns_rr));
    fprintf(log, "%s\tIN\tNS\t%s\n", domain, name);
    offset += sizeof(struct dns_rr);
}

char *qtype_to_a(uint16_t qtype);


/**
 * Afiseaza in formatiile primite de la un server DNS.
 * message si server_ip trebuie sa fi fost obtinute in prealabil
 * cu un apel request_info.
 */
void print_info(const char *message, const char *server_ip)
{
    char domain[DOMSIZE];
    char flag;
    FILE *log = fopen("dns.log", "a");
    const struct dns_header *h = (struct dns_header *) message;
    
    const struct dns_question *q =
        (struct dns_question *) (message + sizeof(struct dns_header) + qname_to_domain(domain, message, sizeof(struct dns_header)));

    fprintf(log, "; %s - %s %s\n", server_ip, domain, qtype_to_a(q->qtype));

    int offset = sizeof(struct dns_header) + qname_to_domain(domain, message, sizeof(struct dns_header)) + sizeof(struct dns_question);

    if (ntohs(h->ancount) > 0) {
        fprintf(log, "\n;; ANSWER SECTION:\n");
    }

    int i;
    for (i = 0; i < ntohs(h->ancount); i++) {
        offset = print_rr(log, message, offset);
    }

    if (ntohs(h->nscount) > 0) {
        fprintf(log, "\n;; AUTHORITY SECTION:\n");
    }

    for (i = 0; i < ntohs(h->nscount); i++) {
        offset = print_rr(log, message, offset);
    }

    if (ntohs(h->arcount) > 0) {
        fprintf(log, "\n;; ADDITIONAL SECTION:\n");
    }

    for (i = 0; i < ntohs(h->arcount); i++) {
        offset = print_rr(log, message, offset);
    }
		fprintf(log, "\n\n");
    fclose(log);
}

/**
 * Functie apelata de print_rr.  Se ocupa de MX.
 */
void print_rr_mx(FILE       *log,
                 const char *domain,
                 const char *message,
                 int         offset)
{

    offset = offset + sizeof(struct dns_rr);
    offset = offset + sizeof(uint16_t);

    char name[DOMSIZE];
    qname_to_domain(name, message, offset);
    fprintf(log, "%s\tIN\tMX\t%d\t%s\n", domain, ntohs(*((uint16_t *) (message + offset))), name);
}

/**
 * Functie apelata de print_rr.  Se ocupa de CNAME.
 */
void print_rr_cname(FILE       *log,
                    const char *domain,
                    const char *message,
                    int         offset)
{
    char name[DOMSIZE];
    qname_to_domain(name, message, offset + sizeof(struct dns_rr));
    fprintf(log, "%s\tIN\tCNAME\t%s\n", domain, name);
    offset += sizeof(struct dns_rr);
}

int set_header(char *message);
                  
/**
 * Functie apelata de print_rr.  Se ocupa de SOA.
 */
void print_rr_soa(FILE       *log,
                  const char *domain,
                  const char *message,
                  int         offset)
{
    char mname[DOMSIZE];
    offset += sizeof(struct dns_rr);
    offset += qname_to_domain(mname, message, offset);

    char rname[DOMSIZE];
    offset += qname_to_domain(rname, message, offset);

    int serial = ntohl(*((uint32_t *) (message + offset)));
    offset += 4;

    int refresh = ntohl(*((uint32_t *) (message + offset)));
    offset += 4;

    int retry = ntohl(*((uint32_t *) (message + offset)));
    offset += 4;

    int expire = ntohl(*((uint32_t *) (message + offset)));
    offset += 4;

    int min = ntohl(*((uint32_t *) (message + offset)));
    offset += 4;

    fprintf(log, "%s\tIN\tSOA\t%s\t%s\t%u\t%u\t%u\t%u\t%u\n", domain, mname, rname, serial,
            refresh, retry, expire, min);
}

int check_header(struct dns_header h);

/**
 * Functie apelata de print_rr.  Se ocupa de A.
 */
void print_rr_a(FILE       *log,
                const char *domain,
                const char *message,
                int         offset);

int qname_to_domain(char *domain, const char *message, int offset);

int dns_valid_format(char* dns);

/**
 * Functie apelata de print_rr.  Se ocupa de TXT.
 */
void print_rr_txt(FILE       *log,
                  const char *domain,
                  const char *message,
                  int         offset)
{
    const struct dns_rr *rr = (struct dns_rr *) (message + offset);
    int size1 = sizeof(struct dns_rr);
    offset += size1;

    const char *jptr = message + offset;
    int size2 = ntohs(rr->rdlength); 
    offset += size2;

    fprintf(log, "%s\tIN\tTXT\t", domain);
    while (jptr != message + offset) {
        unsigned char n = (unsigned char) *jptr++;
        int i = 0;
        while(i < n && jptr != message + offset) {
            fprintf(log, "%c", *jptr++);
            i++;
        }
        fprintf(log, " ");
    }
    fprintf(log, "\n");
}

void print_rr_a(FILE       *log,
                const char *domain,
                const char *message,
                int         offset)
{
    fprintf(log, "%s\tIN\tA\t%s\n",
            domain,
            inet_ntoa(*((struct in_addr *) (message + offset + sizeof(struct dns_rr)))));
    offset += sizeof(struct dns_rr);
}

uint16_t a_to_qtype(const char *qtype);

/**
 * Afiseaza in fisierul de loguri o resursa ceruta.
 * Intoarce offsetul urmatoarei rr.
 */
int print_rr(FILE *log, const char *message, int offset)
{
    char domain[DOMSIZE];

    const struct dns_rr *rr = (struct dns_rr *) (message + offset + qname_to_domain(domain, message, offset));
    offset += qname_to_domain(domain, message, offset);

	  if(ntohs(rr->type) == A) {
		  print_rr_a(log, domain, message, offset);
	  } else if(ntohs(rr->type) == SOA) {
		  print_rr_soa(log, domain, message, offset);
	  } else if(ntohs(rr->type) == TXT) {
		  print_rr_txt(log, domain, message, offset);
	  } else if(ntohs(rr->type) == NS) {
		  print_rr_ns(log, domain, message, offset);
	  } else if(ntohs(rr->type) == MX) {
		  print_rr_mx(log, domain, message, offset);
	  } else if(ntohs(rr->type) == CNAME) {
		  print_rr_cname(log, domain, message, offset);
	  }
    offset += sizeof(struct dns_rr) + ntohs(rr->rdlength);
   
    return offset;
}

/**
 * Functie care seteaza corestulzator headerul unui mesaj de
 * interogare al unui server DNS.
 * Returneaza lungimea unui header (care e fixa).
 */
int set_header(char *message)
{
    struct dns_header *h = (struct dns_header *) message;
    memset(h, 0, sizeof(h));
    h->qdcount = htons(1);      
    h->rd      = 1;             
    h->ra      = 1;
    
    return sizeof(struct dns_header);
}

/**
 * Functia inversa celei de mai sus.  Primeste ca intrari adresa mesajului
 * din protocolul DNS si un offset la locul unde se afla campul in formatul
 * specific.
 * Returneaza lungimea numelui pana la primul pointer, sau pana se termina,
 * daca nu exista pointeri, pentru a gasi rapid punctul de unde incep datele
 * utile de dupa acest nume.
 */
int qname_to_domain(char *domain, const char *message, int offset)
{
    int len = -1;
		const char *p;
    
    for(p = message + offset; *p != 0;) {
        if ((((uint8_t) *p) & 0xC0)) {
            if (len == -1) {
                len = p + 1 - message - offset + 1;
            }
            if(!*p)
            	break;
            p = message + (ntohs(*((uint16_t *) p)) & 0x3FFF);
            if(p)
	            continue;
        }
        memcpy(domain, p + 1, *p);
        domain += *p;
        *domain++ = '.';
        p += *p + 1;
    }
    *domain = '\0';
    if (len == -1) {
        len = p + 1 - message - offset;
    }

    return len;
}

/**
 * Functie care da un nume de server nou din fisierul de configurare.
 * In cazul in care fisierul se termina sau a aparut o eroare, functia
 * intoarce 1.  La urmatorul apel ea va redeschide fisierul.
 * In cazul in care nu apare nicio eroare se returneaza 0.
 */
int get_new_dns_server(char *server_ip)
{
    static FILE *f = NULL;
		char helper;
		
    if (!server_ip) {
        if (f) {
            fclose(f);
        }
        return 0;
    }

    if (!f) {
        f = fopen("dns_servers.conf", "r");
    }

    if (!f) {
        perror("dns_servers.conf");
        return 1;
    }

    char line[DOMSIZE];

    do {
        fgets(line, DOMSIZE, f);
    } while (!feof(f) && line[0] == '#');
		helper = '1';
    if (feof(f)) {
        fclose(f);
        f = NULL;
        return 1;
    }
		if(helper == '1') {
			strcpy(server_ip, line);
		  server_ip[strlen(server_ip) - 1] = '\0';
		  return 0;
		}
    
}

/**
 * Functie inversa celei de mai sus.
 * ATENTIE, sirul intors e unul constant, el nu trebuie modificat.
 */
char *qtype_to_a(uint16_t qtype)
{
		if(ntohs(qtype) == MX) {
			return "MX";
		}
		if(ntohs(qtype) == CNAME) {
			return "CNAME";
		}
		if(ntohs(qtype) == NS) {
			return "NS";
		}
		if(ntohs(qtype) == A) {
			return "A";
		}
		if(ntohs(qtype) == TXT) {
			return "TXT";
		}
		if(ntohs(qtype) == SOA) {
			return "SOA";
		}
    return NULL;
}

/**
 * Transforma din ASCII in intreg fara semn pe 16 biti un tip de cerere DNS.
 * Intregul e in formatul retelei (big endian).
 */
uint16_t a_to_qtype(const char *qtype)
{
    if (!strcmp(qtype, "A")) {
        return A;
    }
    if (!strcmp(qtype, "TXT")) {
        return TXT;
    }
    if (!strcmp(qtype, "MX")) {
        return MX;
    }
    if (!strcmp(qtype, "SOA")) {
        return SOA;
    }
    if (!strcmp(qtype, "NS")) {
        return NS;
    }
    if (!strcmp(qtype, "CNAME")) {
        return CNAME;
    }
    return 100;
}

/**
 * Functie care seteaza corestulzator partea de question unui mesaj de
 * interogare al unui server DNS.
 * Returneaza lungimea lui question (care e variabila).
 */
int set_question(char *message, const char *domain, const char *type)
{
    struct dns_question *q =
        (struct dns_question *) (message + sizeof(struct dns_header) + domain_to_qname(message + sizeof(struct dns_header), domain));
    q->qtype  = htons(a_to_qtype(type));
    q->qclass = htons(1);

    return domain_to_qname(message + sizeof(struct dns_header), domain) + sizeof(struct dns_question);
}

int check_header(struct dns_header h)
{
	h.id == 4 ? h.rd = 1 ? h.qdcount == htons(1) ? 1 : 0 : 0 : 0;
}

/**
 * Transforma un nume de domeniu ASCII in formatul cerut de protocolul DNS.
 * Returneaza lungimea campului nou creat.
 */
int domain_to_qname(char *qname, const char *domain)
{
    strcpy(qname + 1, domain);
		char *kptr = calloc(strlen(qname), sizeof(char));
    char *iptr = qname;
    char *jptr = qname + 1;
    while(*jptr != '\0') {
			if (*jptr == '.') {
        *iptr = jptr - iptr - 1;
        iptr = jptr;
      }
			jptr++;    
    }
    *iptr = jptr - iptr - 1;

    if(*(jptr - 1) == 0) {
    	return jptr - qname;
    } else {
    	return jptr - qname + 1;
    }
}


int main(int argc, char *argv[])
{
		char message[MAXBUF];
    char server_ip[DOMSIZE];
    
    if (argc != 3) {
        return 1;
    }

    request_info(argv[1], argv[2], message, server_ip);
    print_info(message, server_ip);

    return 0;
}
