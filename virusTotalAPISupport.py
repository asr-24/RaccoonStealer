import requests


def main(file):
    url = "https://www.virustotal.com/api/v3/files"
    
    files = {"file": (file, open(file, "rb"), "application/x-msdownload")}
    
    headers = {
        "accept": "application/json",
        "x-apikey": "apikey"
    }
    
    response = requests.post(url, files=files, headers=headers)
    
    response_json = response.text
    
    analysis_url = response_json[response_json.index("https"):-19]
    
    print(analysis_url)
    
    analysis_response = (requests.get(analysis_url, headers=headers)).text

    stats = [
        "harmless",
        "type-unsupported",
        "suspicious",
        "confirmed-timeout",
        "timeout",
        "failure",
        "malicious",
        "undetected"]
    

    analysis_result = {}
    
    for stat in stats:
        pos_in_string = analysis_response.index(stat)+len(stat)-1
        num = []
        for i in range(pos_in_string,len(analysis_response)):
            if (analysis_response[i] == ','):
                break
            elif (analysis_response[i].isnumeric()):
                num.append(analysis_response[i])
            else:
                continue
        
        num = ''.join(num)
        
        analysis_result[stat] = num
        
    print(analysis_result)