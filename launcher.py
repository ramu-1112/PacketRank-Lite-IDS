import subprocess

ips_proc = subprocess.Popen(['sudo','/home/ramu/venv-env/bin/python','/home/ramu/venv-env/ids_mini/ids_dashboard_sniff/main.py'])
if(ips_proc):
    gui_proc = subprocess.Popen(['/home/ramu/venv-env/bin/python', '-m', 'streamlit', 'run', '/home/ramu/venv-env/ids_mini/traceroute_map/view_map.py'])

ips_proc.wait()
gui_proc.wait()