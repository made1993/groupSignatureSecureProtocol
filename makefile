
FLAGS= -Wall -std=gnu99 -pedantic -O3 -Wcomment

SSLLIBS= -lssl -lcrypto
GSLIBS = -lgroupsig

#AUXILIAR

obj/conexion.o: obj src/conexion.c include/conexion.h
	@gcc $(FLAGS) -c -o obj/conexion.o src/conexion.c


#PROTOCOLOS CRIPTOGRAFICOS

cripto: obj/funcionesDH.o obj/funcionesAES.o obj/funcionesRSA.o obj/funcionesGS.o obj/sconexion.o
	@echo "compilados los protocolos criptograficos"

obj/sconexion.o: obj src/sconexion.c include/sconexion.h
	@gcc $(FLAGS) -c -o obj/sconexion.o src/sconexion.c 

obj/funcionesDH.o: obj src/funcionesDH.c include/funcionesDH.h
	@gcc $(FLAGS) -c -o obj/funcionesDH.o src/funcionesDH.c 

obj/funcionesAES.o: obj src/funcionesAES.c include/funcionesAES.h
	@gcc $(FLAGS) -c -o obj/funcionesAES.o src/funcionesAES.c 

obj/funcionesRSA.o: obj src/funcionesRSA.c include/funcionesRSA.h
	@gcc $(FLAGS) -c -o obj/funcionesRSA.o src/funcionesRSA.c

obj/funcionesGS.o: obj src/funcionesGS.c include/funcionesGS.h
	@gcc $(FLAGS) -c -o obj/funcionesGS.o src/funcionesGS.c 

# TESTS

testRSA: obj test/serverRSA.c test/clientRSA.c obj/funcionesRSA.o obj/conexion.o
	@gcc $(FLAGS) -o TestServerRSA test/serverRSA.c obj/funcionesRSA.o obj/conexion.o $(SSLLIBS)	
	@gcc $(FLAGS) -o TestClientRSA test/clientRSA.c obj/funcionesRSA.o obj/conexion.o $(SSLLIBS)

testDH: obj test/serverDH.c test/clientDH.c obj/funcionesDH.o obj/conexion.o
	@gcc $(FLAGS) -o TestServerDH test/serverDH.c obj/* $(SSLLIBS)
	@gcc $(FLAGS) -o TestClientDH test/clientDH.c obj/* $(SSLLIBS)

testAES: obj test/AES.c obj/funcionesAES.o
	@gcc $(FLAGS) -o TestAES test/AES.c obj/funcionesAES.o $(SSLLIBS)

testGS: obj test/serverGS.c test/clientGS.c obj/funcionesGS.o obj/conexion.o
	@gcc $(FLAGS) -o TestServerGS test/serverGS.c obj/* $(GSLIBS) $(SSLLIBS)
	@gcc $(FLAGS) -o TestClientGS test/clientGS.c obj/* $(GSLIBS) $(SSLLIBS)

obj:
	@mkdir obj


#GENERAR CLAVES
RSAkeys:
	@openssl genrsa -out privkey.pem 2048
	@openssl rsa -in privkey.pem -pubout -out pubkey.pub


#LIMPIEZA

mrProper:
	@rm -fv obj/* objS/* objC/* server cliente funcionesDH funcionesAES Test* main funciones* main
	@rm -fv *.txt
#GIT

commit:
	@git add .
	@git commit -m "$(msg)"
	@git push
