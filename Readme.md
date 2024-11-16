# B-Hunters-Subrecon

**This module is used to gathers subdomains for [B-Hunters Framework](https://github.com/B-Hunters/B-Hunters) using [subfinder](https://github.com/projectdiscovery/subfinder) , [Findomain](https://github.com/Findomain/Findomain), [Sublist3r](https://github.com/aboul3la/Sublist3r), [assetfinder](https://github.com/tomnomnom/assetfinder), [Chaos](https://github.com/projectdiscovery/chaos-client), and [vita](https://github.com/junnlikestea/vita).**

## Requirements

To be able to use all the tools remember to update the environment variables with your API keys in `docker-compose.yml` file as some tools will not work well until you add the API keys.

## Usage 

**Note: You can use this tool inside [B-hunters-playground](https://github.com/B-Hunters/B-Hunters-playground)**   
To use this tool inside your B-Hunters Instance you can easily use **docker-compose.yml** file after editing `b-hunters.ini` with your configuration.

# 1. **Build local**
Rename docker-compose.example.yml to docker-compose.yml and update environment variables.

```bash
docker compose up -d
```

# 2. **Docker Image**
You can also run using docker image, You have to add all available API keys you can as this increase the scanning scope
```bash
docker run -e PDCP_API_KEY=chaoskey -d -v $(pwd)/b-hunters.ini:/etc/b-hunters/b-hunters.ini bormaa/b-hunters-subrecon:v1.0
```

## How it works

B-Hunters-Subrecon receives the domain from B-Hunters cli and run enumeration on it   

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/bormaa)
