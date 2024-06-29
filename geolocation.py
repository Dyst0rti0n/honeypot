import requests

def get_geolocation(ip):
    try:
        response = requests.get(f"https://geolocation-db.com/json/{ip}&position=true").json()
        return response.get('country_name', 'Unknown'), response.get('city', 'Unknown')
    except Exception as e:
        return 'Unknown', 'Unknown'
