# B-Hunters-Subrecon

This is the tool that is responsible to gathers subdomains for B-Hunters project using different subdomain eneumeration tools like [subfinder](https://github.com/projectdiscovery/subfinder) , [Findomain](https://github.com/Findomain/Findomain), [Sublist3r](https://github.com/aboul3la/Sublist3r), [assetfinder](https://github.com/tomnomnom/assetfinder), [Chaos](https://github.com/projectdiscovery/chaos-client), and [vita](https://github.com/junnlikestea/vita)


## Requirements

To be able to use all the tools remember to update the environment variables with your API keys in `docker-compose.yml` file as some tools will not work well until you add the API keys.

## Usage 

To use this tool inside your B-Hunters Instance you can easily use docker compose file after editing `b-hunters.ini` with your configuration.
Also you can use it using the docker compose in the main repo of B-Hunters


## How it works

B-Hunters-Subrecon receives the domain from the ui interface or the discord bot when the wildcard is activated for the scan
