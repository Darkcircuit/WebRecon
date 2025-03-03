from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import dns.resolver
import asyncio
import aiohttp
from bs4 import BeautifulSoup
import re
import socket

app = FastAPI()

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with your frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class DomainRequest(BaseModel):
    domain: str

@app.post("/scan/subdomains")
async def scan_subdomains(request: DomainRequest):
    try:
        # Basic subdomain enumeration using DNS
        resolver = dns.resolver.Resolver()
        subdomains = []
        common_subdomains = ["www", "mail", "ftp", "admin", "blog", "dev", "api"]
        
        for sub in common_subdomains:
            try:
                domain = f"{sub}.{request.domain}"
                answers = resolver.resolve(domain, 'A')
                if answers:
                    subdomains.append(domain)
            except:
                continue
                
        return {"subdomains": subdomains}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/dns")
async def scan_dns(request: DomainRequest):
    try:
        resolver = dns.resolver.Resolver()
        records = {}
        
        # Query different DNS record types
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
        for record_type in record_types:
            try:
                answers = resolver.resolve(request.domain, record_type)
                records[record_type] = [str(answer) for answer in answers]
            except:
                records[record_type] = []
                
        return {"dns_records": records}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/urls")
async def scan_urls(request: DomainRequest):
    try:
        async with aiohttp.ClientSession() as session:
            urls = []
            parameters = []
            base_url = f"https://{request.domain}"
            
            async def fetch_url(url):
                try:
                    async with session.get(url) as response:
                        if response.status == 200:
                            text = await response.text()
                            soup = BeautifulSoup(text, 'html.parser')
                            
                            # Extract links and their parameters
                            for link in soup.find_all(['a', 'form']):
                                href = link.get('href') or link.get('action')
                                if href:
                                    # Handle relative URLs
                                    if href.startswith('/'):
                                        full_url = f"{base_url}{href}"
                                    elif href.startswith(('http://', 'https://')):
                                        if request.domain in href:
                                            full_url = href
                                        else:
                                            continue
                                    else:
                                        full_url = f"{base_url}/{href}"
                                    
                                    # Extract URL parameters
                                    parsed_url = urlparse(full_url)
                                    if parsed_url.query:
                                        query_params = parse_qs(parsed_url.query)
                                        for param, values in query_params.items():
                                            parameters.append({
                                                "url": full_url,
                                                "parameter": param,
                                                "example_value": values[0] if values else ""
                                            })
                                    
                                    urls.append(full_url)
                                    
                            # Extract form inputs
                            for form in soup.find_all('form'):
                                form_url = form.get('action') or url
                                if not form_url.startswith(('http://', 'https://')):
                                    if form_url.startswith('/'):
                                        form_url = f"{base_url}{form_url}"
                                    else:
                                        form_url = f"{base_url}/{form_url}"
                                
                                for input_tag in form.find_all(['input', 'textarea']):
                                    param_name = input_tag.get('name')
                                    if param_name:
                                        parameters.append({
                                            "url": form_url,
                                            "parameter": param_name,
                                            "type": input_tag.get('type', 'text'),
                                            "method": form.get('method', 'get').upper()
                                        })
                except:
                    pass
            
            await fetch_url(base_url)
            return {
                "urls": list(set(urls)),
                "parameters": parameters
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/technologies")
async def scan_technologies(request: DomainRequest):
    try:
        async with aiohttp.ClientSession() as session:
            technologies = []
            url = f"https://{request.domain}"
            
            try:
                async with session.get(url) as response:
                    if response.status == 200:
                        # Get response headers
                        headers = response.headers
                        text = await response.text()
                        
                        # Check for common technologies
                        tech_signatures = {
                            'React': 'react',
                            'Angular': 'angular',
                            'Vue.js': 'vue',
                            'jQuery': 'jquery',
                            'Bootstrap': 'bootstrap',
                            'WordPress': 'wp-content',
                            'PHP': 'php',
                            'ASP.NET': 'asp.net',
                            'nginx': 'nginx',
                            'Apache': 'apache'
                        }
                        
                        # Check headers
                        server = headers.get('Server', '')
                        if server:
                            technologies.append(f"Server: {server}")
                            
                        # Check HTML content
                        for tech, signature in tech_signatures.items():
                            if signature.lower() in text.lower():
                                technologies.append(tech)
            except:
                pass
                
            return {"technologies": technologies}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/ports")
async def scan_ports(request: DomainRequest):
    try:
        ports = []
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080]
        
        async def check_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                result = sock.connect_ex((request.domain, port))
                if result == 0:
                    service = socket.getservbyport(port)
                    ports.append({"port": port, "service": service, "state": "open"})
            except:
                pass
            finally:
                sock.close()
        
        tasks = [check_port(port) for port in common_ports]
        await asyncio.gather(*tasks)
        
        return {"ports": sorted(ports, key=lambda x: x["port"])}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/sensitive-files")
async def scan_sensitive_files(request: DomainRequest):
    try:
        sensitive_files = []
        common_paths = [
            ".git/config",
            ".env",
            "robots.txt",
            "sitemap.xml",
            "wp-config.php",
            "config.php",
            "admin/",
            "backup/",
            ".htaccess",
            "phpinfo.php"
        ]

        async with aiohttp.ClientSession() as session:
            async def check_path(path):
                url = f"https://{request.domain}/{path}"
                try:
                    async with session.get(url) as response:
                        if response.status < 400:  # Consider all responses below 400 as "found"
                            sensitive_files.append({
                                "path": path,
                                "status": response.status,
                                "url": url
                            })
                except:
                    pass

            tasks = [check_path(path) for path in common_paths]
            await asyncio.gather(*tasks)

        return {"sensitive_files": sensitive_files}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)