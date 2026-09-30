#!/usr/bin/env python3
"""Ensayos reales con Ncat y captura GUI Wireshark; no genera paquetes sintéticos.
Uso: python3 reproducir.py --ncat /ruta/a/ncat --output /ruta/nueva
Requiere permisos de dumpcap y acceso a la sesión gráfica.
"""
import argparse, datetime, json, os, pathlib, signal, subprocess, time
ap=argparse.ArgumentParser();ap.add_argument('--ncat',default='ncat');ap.add_argument('--output',required=True);args=ap.parse_args()
out=pathlib.Path(args.output).resolve();out.mkdir(parents=True,exist_ok=True)
if list(out.glob('*.pcapng')):raise SystemExit('La carpeta ya contiene capturas; utilice otra para preservarlas.')
events=[];gui_pids=[]
def record(event,**data):
 events.append(dict(time=datetime.datetime.now().astimezone().isoformat(timespec='microseconds'),epoch=time.time(),event=event,**data))
 (out/'eventos.json').write_text(json.dumps(events,ensure_ascii=False,indent=2))
def capture(name,bpf,display):
 path=out/(name+'.pcapng');log=out/(name+'_wireshark.log')
 env=os.environ.copy();env['QT_QPA_PLATFORM']='xcb'
 cmd=['wireshark','-n','-k','-i','lo','-p','-f',bpf,'-a','duration:12','-w',str(path),'-Y',display]
 f=log.open('w');p=subprocess.Popen(cmd,env=env,stdout=f,stderr=f,start_new_session=True);f.close();gui_pids.append(p.pid)
 record('capture_start',name=name,command=cmd,pid=p.pid)
 for _ in range(100):
  if path.exists() and path.stat().st_size>0:break
  if p.poll() is not None:raise RuntimeError(log.read_text())
  time.sleep(.1)
 else:raise RuntimeError('La captura no inició: '+log.read_text())
 time.sleep(.3);return name,log
def finish(cap):
 name,log=cap
 for _ in range(150):
  if 'Capture stopped' in log.read_text():break
  time.sleep(.1)
 else:raise RuntimeError('No se confirmó el fin de '+name)
 record('capture_stopped',name=name)
 print('Captura finalizada:',name,flush=True)
def start(name,role,udp=False,listen=False):
 cmd=[args.ncat,'-4','-n','-v']+(['-u'] if udp else [])+(['-l'] if listen else [])+['127.0.0.1','12001' if udp else '12000']
 stdout=(out/(name+'_'+role+'_stdout.txt')).open('wb');stderr=(out/(name+'_'+role+'_stderr.txt')).open('wb')
 p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=stdout,stderr=stderr);stdout.close();stderr.close();record('process_start',name=name,role=role,command=cmd,pid=p.pid);return p
def send(p,name,role,message):
 record('send_line',name=name,role=role,payload=message,length=len(message.encode()))
 p.stdin.write(message.encode());p.stdin.flush();time.sleep(.4)
def stop(p,name,role):
 if p.poll() is None:
  record('SIGINT',name=name,role=role);p.send_signal(signal.SIGINT)
  p.wait(timeout=3)
 record('process_exit',name=name,role=role,returncode=p.returncode)
def exchange(name,udp=False,one=False):
 port=12001 if udp else 12000;proto='udp' if udp else 'tcp'
 cap=capture(name,f'{proto} port {port}',f'{proto}.port == {port}')
 server=start(name,'servidor',udp,True);time.sleep(.35)
 client=start(name,'cliente',udp);time.sleep(1.2)
 record('idle_before_data_end',name=name)
 send(client,name,'cliente','Hola desde Ncat\n')
 if not one:
  send(server,name,'servidor','Recibido en el servidor\n')
  send(client,name,'cliente','Segundo mensaje\n')
  send(server,name,'servidor','Segunda respuesta\n')
  send(client,name,'cliente','Fin de la prueba\n')
  send(server,name,'servidor','Prueba completada\n')
 time.sleep(.8);stop(client,name,'cliente');time.sleep(1.2)
 stop(server,name,'servidor');finish(cap)
record('environment',ncat_version=subprocess.check_output([args.ncat,'--version'],text=True,stderr=subprocess.STDOUT).strip(),kernel=subprocess.check_output(['uname','-srmo'],text=True).strip())
(out/'puertos_antes.txt').write_text(subprocess.check_output(['ss','-lntup','sport = :12000 or sport = :12001'],text=True))
exchange('tcp_intercambio');exchange('udp_intercambio',udp=True)
name='puertos_cerrados';cap=capture(name,'tcp port 12000 or udp port 12001 or (icmp and host 127.0.0.1)','tcp.port == 12000 || udp.port == 12001 || icmp')
p=start(name,'cliente_tcp');p.wait(timeout=3);record('process_exit',name=name,role='cliente_tcp',returncode=p.returncode)
time.sleep(.5);p=start(name,'cliente_udp',udp=True);time.sleep(1.2);send(p,name,'cliente_udp','Hola desde Ncat\n');time.sleep(1.2);stop(p,name,'cliente_udp');finish(cap)
exchange('tcp_una_frase',one=True);exchange('udp_una_frase',udp=True,one=True)
(out/'puertos_despues.txt').write_text(subprocess.check_output(['ss','-lntup','sport = :12000 or sport = :12001'],text=True))
(out/'gui_pids.json').write_text(json.dumps(gui_pids));print('Ensayos completados.',flush=True)
