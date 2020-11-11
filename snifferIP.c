#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/ioctl.h>
#include<sys/socket.h>
#include<net/if.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<linux/if_ether.h>
#include<pthread.h>
#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header
#include<unistd.h>

//Nombre de adaptador wlp2s0
#define MAXLINE 65536  //Tamaño maximo de trama


//Variable Global a la que accederan ambos Hilos


char buffer[2000][MAXLINE]; //Es el buffer donde guardare los paquetes IP, puedo recibir hasta 2000.
int tamanios[2000];
int lectura_buffer = 1;		//Simula semaforo de procesos
//Variables para conteo de protocolos en Trama Ethernet
	int nipv4=0;
	int nipv6=0;
	int narp=0;
	int ncontrolf=0;
	int nseguridad=0;
	int ndesconocido=0;

//Variables para conteo de protocolos en Trama IP

    int ICMP=0;
    int IGMP=0;
    int IP=0;
    int TCP=0;
    int UDP=0;
    int IPv6=0;
    int OSPF=0;
    int otros=0;

// Variables para contar tamaños
	int tamanio159=0;
	int tamanio639=0;
	int tamanio1279=0;
	int tamanio5119=0;
	int tamaniomay=0;

//Estructura para contar paquetes por cada direccion IP
typedef struct userIP{
	
	int paquetes_recibidos;
	int paquetes_enviados;
}

//Archivo para guardar los datos
FILE *Archivo;

//Estructura para guardar los datos que mete el usuario
typedef struct datosUser{
	int	num_paquetes;
	char nom_de_adaptador[10];
}datosUser;



//Funciones extra para el analizador
void IdProtocolo (uint16_t proto, int tipo){

	if(tipo == 0){
		switch(proto){
		
				case 2048:
					
					printf("(IPv4)\n\n");
					nipv4++;
					break;
					
				case 34525:
					
					printf("(IPv6)\n\n");
					nipv6++;
					break;
					
				case 2054:
					
					printf("(ARP)\n\n");
					narp++;
					break;
					
				case 34824:
					
					printf("(Control de Flujo)\n\n");
					ncontrolf++;
					break;
				
				case 35045:
					
					printf("(Seguridad MAC)\n\n");
					nseguridad++;
					break;
				

				default: 
					printf("(Desconocido)\n\n");
					ndesconocido++;
		}
	}
	else if(tipo == 1){
		switch(proto){
		
				case 2048:
					fprintf(Archivo,"(IPv4)\n\n");
					break;
					
				case 34525:
					fprintf(Archivo,"(IPv6)\n\n");
					break;
					
				case 2054:			
					fprintf(Archivo,"(ARP)\n\n");
					break;
					
				case 34824:
					fprintf(Archivo,"(Control de Flujo)\n\n");
					break;
				
				case 35045:
					fprintf(Archivo,"(Seguridad MAC)\n\n");
					break;
				

				default: 
					fprintf(Archivo,"(Desconocido)\n\n");
		}
	}
}

//FUncion para revisar los protocolos de capa superior en la cabecera IPv4
void conteoProtocolIP(uint8_t protocolo)
{
	//Get the IP Header part of this packet
	switch (protocolo) //Check the Protocol and do accordingly...
	{
		case 1:  //ICMP Protocol
			ICMP++;
			printf("Protocol ICMP\n");
			break;
		case 2:  //IGMP Protocol
			IGMP++;
            printf("Protocol IGMP\n");
			break;
		case 4: //IP Protocol
            IP++;
            printf("Protocol IP\n");
            break;
		case 6:  //TCP Protocol
			TCP++;
            printf("Protocol TCP\n");
			break;
		case 17: //UDP Protocol
			UDP++;
            printf("Protocol UDP\n");
			break;
		case 41: //IPv6 Protocol
            IPv6++;
            printf("Protocol IPv6\n");
            break;
        case 89:   //OSPF Protocol
            OSPF++;
            printf("Protocol OSPF\n");
            break;
		default: //Some Other Protocol like ARP etc.
			otros++;
            printf("Protocol Others...\n");
    }
    

}




//Funcion que estara Capturando los Datos
void capturador(struct datosUser *datosP){
	
	//Variables para el modo prosmicuo y analizar trama
	struct ifreq ethreq;
	struct ethhdr trama; //Estructura donde tiene DD, DS, L/T, Payload
    //struct iphdr tramaip; //Estructura donde tiene VER, HLEN, TIPO, Longitud Total y mas...
	//Variables para el socket crudo
	int idsocket; //Socket capturador
	 //Buffer para recibir datos de 1024 bytes
    int sizeB;
    int i=0;
    int saddr_size;
    struct sockaddr_in source_socket_address;
    struct sockaddr_in dest_socket_address;
	struct sockaddr saddr;
    
	idsocket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	 if(idsocket == -1){
		printf("Error al generar el socket\n\n");
		exit(1);
	 }
	
	
	//Modo Prosmicuo ACTIVO
	strncpy (ethreq.ifr_name, datosP->nom_de_adaptador, IFNAMSIZ);
	ioctl (idsocket,SIOCGIFFLAGS, &ethreq);
	ethreq.ifr_flags |= IFF_PROMISC;
	ioctl (idsocket, SIOCSIFFLAGS, &ethreq);
	
	//Recibiendo paquetes
	while( i < (datosP->num_paquetes) ){
	
		saddr_size = sizeof saddr;
		sizeB = recvfrom(idsocket , (char *)buffer[i] , MAXLINE, 0 , &saddr , &saddr_size);

		tamanios[i]=sizeB;
      	buffer[i][sizeB]='\0';
		printf("%d.-El buffer trae: %s\nTamanio: %d \n\n",i+1,buffer[i],sizeB);
		
		i++;
	}
	lectura_buffer = 0;
	

	//pthread_exit(NULL);
}

//Función que analizara la trama

void analizador(struct datosUser *datosP){

	int j=0;
	struct ethhdr *ethernet_header;
    struct iphdr *tramaip; //Estructura donde tiene VER, HLEN, TIPO, Longitud Total y mas...
    struct sockaddr_in source,dest; //Estructura para mis variables de fuente y destino
	int size_trama=0;
	char direccion_dest[18];
	char aux_dest[9];
	char direccion_orig[18];
	char aux_orig[9];
	uint16_t protocolo;
	int num802=0;
	int ethernetII=datosP->num_paquetes;
    char auxbuffer[MAXLINE];//Buffer de ayuda momentaneo
	int cargautilIP=0;
	

	
	Archivo = fopen("sniffer.txt","a+");
	if(Archivo ==NULL){
		printf("No se creo el archivo");
	}
	else{
		while(lectura_buffer){
			//While que sirve de semaforo
		}
		printf("----------INICIANDO ANALIZADOR----------\n\n");

		//Escritura incial
		fprintf(Archivo,"-------------------REPORTE DE SNIFFER-------------------\n\n");
		fprintf(Archivo,"Tarjeta de adaptador de red: %s\n",datosP->nom_de_adaptador);
		fprintf(Archivo,"Num. de tramas leídas: %d\n\n",datosP->num_paquetes);
		fprintf(Archivo,"Tramas Ethernet II: %d\n\n",ethernetII);
		j=0;
		//Analizador para conteo de Tramas
		while(j < (datosP->num_paquetes)){

			if(tamanios[j]>45){

                //Inicializamos la cabecera ethernet con la struct
                ethernet_header = (struct ethhdr *)buffer[j];

                protocolo = htons(ethernet_header->h_proto);
				printf("Protocolo: 0x%04X ",protocolo);
				IdProtocolo(protocolo,0);
                
                if(protocolo == 2048){
                    printf("\nTrama %d: %s\nPayload: %d\n",j+1,buffer[j],tamanios[j]);
                }				
				
			}
			j++;
		}

		//Imprime cuantas tramas son IPv4 leidas desde trama ethernet
		printf("Tramas de IPv4: %d\n\n",nipv4);
		fprintf(Archivo,"Tramas de IPv4: %d\n",nipv4);//Imprime cuantas tramas son IPv4 leidas desde trama ethernet
		
		j=0;
        while (j < (datosP->num_paquetes)){

            if(tamanios[j]>45){
                //Comenzamos a analizar la trama IPv4, que es el payload de ethernet
                tramaip = (struct iphdr *)(buffer[j] + sizeof(struct ethhdr)); //Estructura para ahorita XD
                //Se apunta en el encapsulado del datagrama IP, saltar 14 bytes que tienen la cabecera ETHERNET
                //
                memset(&source, 0, sizeof(source));
                source.sin_addr.s_addr = tramaip->saddr;
                
                memset(&dest, 0, sizeof(dest));
                dest.sin_addr.s_addr = tramaip->daddr;

                printf("---------Trama %d: ---------\n\n",j+1);
                printf("Version: %d\n",(unsigned int)tramaip->version);
                printf("Hlen: %d\n",((unsigned int)tramaip->ihl)*4);
                printf("Tipo de Servicio: %d\n",(unsigned int)tramaip->tos);
                printf("Longitud Total: %d\n",ntohs(tramaip->tot_len));
                printf("Identificacion: %d\n",ntohs(tramaip->id));
                printf("Bandera y Dezplazamiento de Fragmentacion: 0x%04x\n",ntohs(tramaip->frag_off));
                printf("Tiempo de vida: %d\n",(unsigned int)tramaip->ttl);
                printf("Protocolo de Capa de superior: 0x%02x ",tramaip->protocol);
                conteoProtocolIP(tramaip->protocol);//Contador de protocolos de capa superior
                printf("Checksum: %d\n",ntohs(tramaip->check));
                printf("IP Fuente: %s\n",inet_ntoa(source.sin_addr));
                printf("IP Destino: %s\n",inet_ntoa(dest.sin_addr));
                
				cargautilIP = ntohs(tramaip->tot_len) - (((unsigned int)tramaip->ihl)*4);
				
				fprintf(Archivo,"---------Trama %d: ---------\n\n",j+1);
				fprintf(Archivo,"IP Fuente: %s\n",inet_ntoa(source.sin_addr));
				fprintf(Archivo,"IP Destino: %s\n",inet_ntoa(dest.sin_addr));
				fprintf(Archivo,"Longitud de Cabecera: %d bytes",((unsigned int)tramaip->ihl)*4);
				fprintf(Archivo,"Longitud Total del Datagrama IP: %d bytes",ntohs(tramaip->tot_len));
				fprintf(Archivo,"Identificador: %d\n",ntohs(tramaip->id));
				fprintf(Archivo,"Tiempo de vida: %d\n",(unsigned int)tramaip->ttl);
				fprintf(Archivo,"Protocolo de Capa de superior: 0x%02x \n",tramaip->protocol);
				fprintf(Archivo,"Longitud de carga util: %d\n",cargautilIP);
				fprintf(Archivo,"Tipo de Servicio: %d\n",(unsigned int)tramaip->tos);
				fprintf(Archivo,"Bandera y Dezplazamiento de Fragmentacion: 0x%04x\n",ntohs(tramaip->frag_off));
				//Mascara al segmento de banderas (3 bits mas significativos de los 16 de la variable) 
				//Se usa 0x8000 = 1000 0000 0000 0000, bit reservado
				//Se usa 0x4000 = 0100 0000 0000 0000, bit reservado
				//Se usa 0x2000 = 0010 0000 0000 0000, bit reservado
				//Se usa 0x1FFF = 0001 1111 1111 1111, cuando lo usamos en los if dentro del tercer if, es para revisar el valor que trae el fragmento (Primero o Intermedio)(Ya que se aprobo que tiene más fragmentos)
				//Se usa 0x1FFF = 0001 1111 1111 1111, Se usa cuando se lee que ya es el ultimo fragmento, porque ya no viene bit de mas fragmentos pero viene un valor de donde contar.
				if((ntohs(tramaip->frag_off) & 0x8000) > 0){
					fprtinf(Archivo,"Bandera de bit reservado\n");
				}
				else if ((ntohs(tramaip->frag_off) & 0x4000) > 0){
					fprintf(Archivo,"Datagrama no se puede fragmentar\n");
				}
				else if ((ntohs(tramaip->frag_off) & 0x2000) > 0){
					fprintf(Archivo,"Más Fragmentos... \n");
					if ((ntohs(tramaip->frag_off) & 0x1FFF) == 0)
					{
						fprintf(Archivo,"Primer Fragmento\n");
					}else{
						fprintf(Archivo,"Fragmento Intermedio");
					}
					
				}else if((ntohs(tramaip->frag_off) & 0x1FFF) > 0){
					fprintf(Archivo,"Ultimo Fragmento\n");
				}
				else{
					fprintf(Archivo,"Único Fragmento\n");
				}

				fprintf(Archivo,"Primer Byte del datagrama IP: %02x",buffer[j] + sizeof(struct ethhdr));
				fprintf(Archivo,"Último Byte del datagrama IP: %02x",buffer[j] + sizeof(struct ethhdr) + ntohs(tramaip->tot_len)-1);
				
				


            }
            j++;
            
        }

        printf("--------Conteo de Protocolos--------\n\n");
        printf("ICMP: %d\n",ICMP);
        printf("IGMP: %d\n",IGMP);
        printf("IP: %d\n",IP);
        printf("TCP: %d\n",TCP);
        printf("UDP: %d\n",UDP);
        printf("IPv6: %d\n",IPv6);
        printf("OSPF: %d\n",OSPF);
        printf("Otros: %d\n",otros);
        
        
		
	}

    fclose(Archivo);
	

}



int main(){


	datosUser datosP;
    char cierre[50]="/sbin/ifconfig ";
    pthread_t hiloCapturador;
    pthread_t hiloAnalizador;
    //int aux=0;

	printf("Ingrese el num de paquetes a analizar: ");
	scanf("%d",&datosP.num_paquetes);
	printf("Ingrese el nombre de sus adaptador de red: ");
	while (getchar() != '\n');
	fgets(datosP.nom_de_adaptador,10,stdin);
	strtok(datosP.nom_de_adaptador, "\n");
	
	printf("\nLEIDO\n\nNum Paq: %d\nNombre de Adaptador: %s\n",datosP.num_paquetes,datosP.nom_de_adaptador);
	
	//Creamos el Hilo capturador, donde lo mandamos a la función capturador y las variables de los datos de usuarios con apuntador
	pthread_create(&hiloCapturador,NULL,(void*)capturador,(void*)&datosP);
	pthread_create(&hiloAnalizador,NULL,(void*)analizador,(void*)&datosP);
	pthread_join(hiloCapturador,NULL);
	pthread_join(hiloAnalizador,NULL);
	
	//Creamos el string donde se quita el modo prosmicuo
	strcat(cierre,datosP.nom_de_adaptador);
	strcat(cierre," -promisc");
	system(cierre);

	return 0;
}