import subprocess
import requests
import time
import os

NGROK_PATH = 'ngrok'  
NGROK_API_URL = 'http://127.0.0.1:4040/api/tunnels' # can pipe to personal xmonad windows
_ngrok_process = None

def start_ngrok(port):
    global _ngrok_process

  try:
        _ngrok_process = subprocess.Popen([NGROK_PATH, 'http', str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        print("[ngrok.py] Error: ngrok not found. Please install ngrok and add it to your PATH.")
        return None

for _ in range(20):
        try:
            url = get_public_url()
            if url:
                return url
        except Exception:
            pass
        time.sleep(0.5)
    print("[ngrok.py] Error: ngrok tunnel did not start in time.")
    return None

def get_public_url():
    try:
        resp = requests.get(NGROK_API_URL)
        tunnels = resp.json().get('tunnels', [])
        for tunnel in tunnels:
            if tunnel.get('proto') == 'https':
                return tunnel.get('public_url')
            elif tunnel.get('proto') == 'http':
                url = tunnel.get('public_url')

      return url if 'url' in locals() else None
    except Exception as e:
        return None

def stop_ngrok():
    global _ngrok_process
    if _ngrok_process:
        _ngrok_process.terminate()
        _ngrok_process.wait()
        _ngrok_process = None

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Start an ngrok tunnel for a given port.')
    parser.add_argument('port', type=int, help='Local port to tunnel')
    args = parser.parse_args()
    url = start_ngrok(args.port)
    if url:
        print(f'ngrok tunnel started: {url}')
        print('Press Ctrl+C to stop.')
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            stop_ngrok()
            print('ngrok tunnel stopped.')
    else:
        print('Failed to start ngrok.') 
