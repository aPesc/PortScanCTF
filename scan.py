### IMPORTAMOS EL PATH DONDE SE ENCUENTRAN LOS SITE-PACKAGES ###
import sys
sys.path.append(".venv/lib/python3.11/site-packages")

### IMPORTAMOS OS, JSON Y NMAP ###
import os
import json
import nmap

### FUNCIONES ###
def escaneodepuertos(scan_ip, scan_arguments):
    try:
        # INIZIALIZAMOS EL OBJETO NMAP PORTSCANNER
        nm = nmap.PortScanner()
        # IMPRIMIMOS MENSAJE DICIENDO QUE EL ESCANEO A INICIADO
        print(f"Iniciando escaneo para {scan_ip}...")
        # RELIZAMOS EL ESCANEO DE PUERTOS
        nm.scan(scan_ip, arguments=scan_arguments)
        # IMPRIMIMOS MENSAJE DICIENDO QUE EL ESCANEO A FINALIZADO
        print(f"Escaneo de puertos para {scan_ip} completado.")
        # CREAMOS UNA LISTA PARA ALMACENAR LOS DATOS DEL ESCANEO
        output_data = []
        # COMPROBAMOS SI EL ARCHIVO JSON YA EXISTE
        if os.path.exists('output.json'):
            # ABRIMOS EL ARCHIVO JSON EN MODO LECTURA
            with open('output.json', 'r') as existing_json:
                # CARGAMOS LOS DATOS EXISTENTES DESDEEL ARCHIVO JSON
                output_data = json.load(existing_json)

        for host in nm.all_hosts():
            # OBTENEMOS LA INFORMACIÓN DEL ESCANEO PARA EL HOST ACTUAL
            scan_result = nm[host]

            for proto in scan_result.all_protocols():
                if proto in scan_result:
                    ports = scan_result[proto]
                    for port, estado in ports.items():
                        # UTILIZAMOS DIRECTAMENTE nm[host][proto][port] PARA ACCEDER A LA INFORMACIÓN ESPECÍFICA DEL PUERTP
                        port_info = nm[host][proto][port]

                        row_data = {
                            'host': host,
                            'hostname': port_info.get('hostname', ''),
                            'hostname_type': port_info.get('hostname_type', ''),
                            'protocol': proto,
                            'port': port,
                            'name': port_info.get('name', ''),
                            'state': estado['state'],
                            'product': port_info.get('product', ''),
                            'extrainfo': port_info.get('extrainfo', ''),
                            'reason': port_info.get('reason', ''),
                            'version': port_info.get('version', ''),
                        }

                        # VERIFICAMOS SI LA CONVINACIÓN DE HOSTS Y PUERTO YA EXISTE EN LA LISTA
                        if row_data not in output_data:
                            output_data.append(row_data)

        with open('output.json', 'w') as json_file:
            json.dump(output_data, json_file, indent=2)

    except nmap.PortScannerError as e:
        print(f"Error durante el escaneo: {e}")

def escaneodehostsup(scan_network):
    try:
        nm = nmap.PortScanner()
        print(f"Iniciando escaneo de ping para {scan_network}...")
        nm.scan(scan_network, arguments="-sn")

        output_data = []
        for host in nm.all_hosts():
            row_data = {
                'host': host,
                'status': nm[host].state(),
            }

            if 'hostnames' in nm[host]:
                row_data['hostnames'] = nm[host]['hostnames']

            output_data.append(row_data)

        with open('output_hosts_up.json', 'w') as json_file:
            json.dump(output_data, json_file, indent=2)

        print(f"Escaneo de ping para {scan_network} completado.")

    except nmap.PortScannerError as e:
        print(f"Error durante el escaneo de ping: {e}")


### PP ###
option = input("0.-Salir.\n1.-Escanear todos los hosts de la red para ver los que esten en estado 'up' (Las maquinas windows y algun otro puede que no aparezcan).\n2.-Escanear todos los puertos abiertos de un host en concreto.\n3. Realizar un escaneo de detección de servicios.¿Que es lo que quieres hacer? ")

while True:
    match option:
        case "0":
            break
        case "1":
            # SOLICITAMOS LA RED A ESCANEAR Y LLAMAMOS A LA FUNCION 
            scan_network = input("Cual es la red a escanear(e.g.: 192.168.1.0/24)? ")
            escaneodehostsup(scan_network)
            break
        case "2":
            # SUBMENU PARA LA OPCION 2: ESCANEAR PUERTOS DE UN HOST
            sub_option = input("Como quieres ingresar la dirección IP?\n1. Manualmente\n2. Desde el archivo de 'output_hosts_up.json'\nSelecciona la opción: ")
            if sub_option == "1":
                scan_ip = input("Ingrese la dirección IP manualmente: ")
                scan_arguments = '-Pn'
                escaneodepuertos(scan_ip, scan_arguments)
            elif sub_option == "2":
                try:
                    # LEEMOS EL ARCHIVO DE HOSTS Y MOSTRAMOS LAS IPS DISPONIBLES
                    with open('output_hosts_up.json', 'r') as hosts_file:
                        hosts_data = json.load(hosts_file)
                    print("IPs disponibles:")
                    for index, host_data in enumerate(hosts_data, 1):
                        print(f"{index}. {host_data['host']}")
                    # EL USUARIO SELECCIONA UNA IP Y REALIZAMOS EL ESCANEO DE PUERTOS
                    choice = int(input("Seleccione el número correspondiente a la IP que desea escanear: "))
                    selected_ip = hosts_data[choice - 1]['host']
                    scan_arguments = '-Pn'
                    escaneodepuertos(selected_ip, scan_arguments)
                except (FileNotFoundError, json.JSONDecodeError, IndexError, ValueError) as e:
                    print(f"Error al leer el archivo de hosts: {e}")
            else:
                print("Opción no válida.")
            break
        case _:
            print("La elección no es correcta")
            break


