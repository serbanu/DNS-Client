build:
	gcc -o my_dns_client my_dns_client.c
run:
	./my_dns_client yahoo.com MX
clean:
	rm my_dns_client
