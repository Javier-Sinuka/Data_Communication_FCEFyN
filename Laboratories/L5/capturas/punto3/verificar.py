#!/usr/bin/env python3
"""Contrasta capturas pcapng, exportaciones Wireshark y salidas de Ncat."""
import base64,hashlib,json,pathlib,struct
root=pathlib.Path(__file__).resolve().parent
expected={'tcp_intercambio':18,'udp_intercambio':6,'puertos_cerrados':4,'tcp_una_frase':8,'udp_una_frase':1}
messages=[b'Hola desde Ncat\n',b'Recibido en el servidor\n',b'Segundo mensaje\n',b'Segunda respuesta\n',b'Fin de la prueba\n',b'Prueba completada\n']
frames={};details={};summary=[];hashes=[]
for name,count in expected.items():
 path=root/(name+'.pcapng');data=path.read_bytes();pos=0;packets=[]
 assert data[8:12]==b'\x4d\x3c\x2b\x1a','Se espera pcapng little-endian'
 while pos<len(data):
  typ,length=struct.unpack_from('<II',data,pos);assert length>=12 and struct.unpack_from('<I',data,pos+length-4)[0]==length
  if typ==6:
   caplen,wirelen=struct.unpack_from('<II',data,pos+20);assert caplen==wirelen
   packets.append(data[pos+28:pos+28+caplen])
  pos+=length
 export=json.loads((root/(name+'_analisis.json')).read_text())
 assert packets==[base64.b64decode(row['result']['bytes']) for row in export[2:]]
 assert len(packets)==count;frames[name]=packets;details[name]=[]
 hashes.append(hashlib.sha256(data).hexdigest()+'  '+path.name)
 for i,b in enumerate(packets,1):
  assert b[:12]==b'\0'*12 and b[12:14]==b'\x08\x00'
  iplen=(b[14]&15)*4;assert iplen==20;assert b[26:34]==b'\x7f\0\0\1'*2
  assert int.from_bytes(b[16:18],'big')==len(b)-14
  proto=b[23];st=14+iplen
  if proto in [6,17]:
   src,dst=struct.unpack_from('!HH',b,st);hdr=(b[st+12]>>4)*4 if proto==6 else 8
   payload=b[st+hdr:];flags=b[st+13] if proto==6 else 0
   if proto==17:assert int.from_bytes(b[st+4:st+6],'big')==len(b)-st
  else:
   assert proto==1;src=dst=0;hdr=8;payload=b[st+8:];flags=0
  details[name].append(dict(proto=proto,src=src,dst=dst,hdr=hdr,payload=payload,flags=flags))
  summary.append('\t'.join(map(str,[name,i,{6:'TCP',17:'UDP',1:'ICMP'}[proto],len(b),src,dst,hdr,len(payload),hex(flags),payload.hex()])))
for name in ['tcp_intercambio','udp_intercambio']:
 d=details[name];assert [x['payload'] for x in d if x['payload']]==messages
 assert (root/(name+'_servidor_stdout.txt')).read_bytes()==b''.join(messages[::2])
 assert (root/(name+'_cliente_stdout.txt')).read_bytes()==b''.join(messages[1::2])
assert [x['flags'] for x in details['tcp_intercambio']]==[2,18,16,24,16,24,16,24,16,24,16,24,16,24,16,17,17,16]
assert details['tcp_intercambio'][3]['hdr']==32
assert details['tcp_intercambio'][0]['hdr']==details['tcp_intercambio'][1]['hdr']==40
assert details['udp_intercambio'][0]['hdr']==8
for name in ['tcp_una_frase','udp_una_frase']:
 assert [x['payload'] for x in details[name] if x['payload']]==messages[:1]
 assert (root/(name+'_servidor_stdout.txt')).read_bytes()==messages[0]
assert [x['flags'] for x in details['tcp_una_frase']]==[2,18,16,24,16,17,17,16]
a=frames['puertos_cerrados'];assert a[1][47]==0x14 and a[3][34:36]==b'\x03\x03'
assert a[3][42:]==a[2][14:],'ICMP debe incluir el datagrama original'
for role in ['cliente_tcp','cliente_udp']:
 assert 'Connection refused' in (root/('puertos_cerrados_'+role+'_stderr.txt')).read_text()
(root/'SHA256SUMS.txt').write_text('\n'.join(hashes)+'\n')
(root/'resumen_paquetes.tsv').write_text('captura\ttrama\tprotocolo_IP\tbytes_trama\tpuerto_origen\tpuerto_destino\tbytes_cabecera_transporte\tbytes_payload\tflags_TCP\tpayload_hex\n'+'\n'.join(summary)+'\n')
result='Verificación satisfactoria: 37 paquetes reales en 5 capturas.\n'+\
'PCAPNG y bytes exportados por Wireshark coinciden; sin truncamiento.\n'+\
'TCP/UDP principales: seis payloads idénticos; 49 bytes del cliente y 60 del servidor.\n'+\
'Salidas de ambos procesos Ncat coinciden con los datos capturados.\n'+\
'TCP: SYN/SYN-ACK/ACK; seis segmentos con datos y seis ACK; FIN-ACK/FIN-ACK/ACK.\n'+\
'Una frase: 8 paquetes TCP frente a 1 UDP; payload idéntico de 16 bytes.\n'+\
'Puertos cerrados: SYN/RST-ACK, UDP/ICMP tipo 3 código 3; ICMP contiene el IPv4 original.\n'+\
'Checksums de transporte no validados: la captura local puede contener contribuciones parciales.\n'
(root/'verificacion.txt').write_text(result);print(result)
