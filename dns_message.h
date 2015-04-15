/**
 * Protocoale de comunicatie -- Tema 4 2014
 * @author	Mardaloescu Serban, 334CA
 */

#ifndef DNS_MESSAGE_H
#define DNS_MESSAGE_H

/* -- Query & Resource Record Type: -- */

#define	A     1                 /* IPv4 address */
#define	NS    2                 /* Authoritative name server */
#define	CNAME 5                 /* Canonical name for an alias */
#define	PTR   12                /* Domain name pointer. */
#define	MX    15                /* Mail exchange */
#define SOA   6                 /* Start Of a zone of Authority */
#define	TXT   16                /* Text strings */


/* -- Define DNS message format -- */

/** Header section format
    1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ANCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
struct dns_header {
    /* schimba (LITTLE/BIG ENDIAN) folosind htons/ntohs */
    uint16_t id;                /* identification number */

    /* LITTLE -> BIG ENDIAN: inversare 'manuala' ptr byte-ul 1 din flag-uri */
    uint8_t rd     :1;          /* recursion desired */
    uint8_t tc     :1;          /* truncated message */
    uint8_t aa     :1;          /* authoritive answer */
    uint8_t opcode :4;          /* purpose of message */
    uint8_t qr     :1;          /* query/response flag: 0=query; 1=response */

    /* LITTLE -> BIG ENDIAN: inversare 'manuala' ptr byte-ul 2 din flag-uri */
    uint8_t rcode :4;
    uint8_t z     :3;
    uint8_t ra    :1;

    /* schimba (LITTLE/BIG ENDIAN) folosind htons/ntohs */
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

/** Question section format
    1  1  1  1  1  1
    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                     QNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QTYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     QCLASS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
struct dns_question {
    /* qname variabil */
    uint16_t qtype;
    uint16_t qclass;
};

/** Resource record format
   1  1  1  1  1  1
   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                                               |
   /                                               /
   /                      NAME                     /
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                      TYPE                     |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                     CLASS                     |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                      TTL                      |
   |                                               |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   |                   RDLENGTH                    |
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
   /                     RDATA                     /
   /                                               /
   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
struct dns_rr {
    /* name variabil */
    uint16_t type;
    uint16_t class;
    uint32_t ttl;
    uint16_t rdlength;
    /* rdata variabil */
} __attribute__ ((__packed__));

#endif  /* DNS_MESSAGE_H */
