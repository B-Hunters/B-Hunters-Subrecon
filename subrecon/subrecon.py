from b_hunters.bhunter import BHunters
from karton.core import Task
from .__version__ import __version__
import subprocess
import shutil
import re



class subrecon(BHunters):
    """
    B-Hunters Subrecon developed by Bormaa
    """

    identity = "B-Hunters-subrecon"
    version = __version__
    persistent = True
    filters = [
        {
            "type": "domain", "stage": "new"
        }
    ]

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
    def findusbcommand(self,domain):
        result=[]
        active=[]
        try:
            folder1=self.generate_random_filename()
            # print(folder1)
            output=subprocess.run(["/app/findsubs.sh",folder1,domain], capture_output=True, text=True)
            # print(output)
            # data=output.stdout.split("\n")
            try:
                
                # Open the file in read mode
                with open(folder1+"/all.txt", "r") as file:
                    # Read the contents of the file
                    file_contents = file.read()
                    data=file_contents.split("\n")
                    result=data
                # Open the file in read mode
                with open(folder1+"/httpx.txt", "r") as file2:
                    # Read the contents of the file
                    file_contents = file2.read()
                    data2=file_contents.split("\n")
                    active=data2
            except FileNotFoundError:
                print("File not found.")
            except IOError as e:
                print("Error:", e)
            shutil.rmtree(folder1)

        except Exception as e:
            print("error ",e)
            raise Exception(e)
            # result=[]
        return result,active
                    
    def scan(self,url):        
        result,active=self.findusbcommand(url)
        if result !=[]:
            return result,active
        return [],[]
        
    def process(self, task: Task) -> None:
        domain = task.payload_persistent["domain"]
        scanid = task.payload["scan_id"]
        scantype = task.payload_persistent["scantype"]
        self.update_task_status(domain,"Started")

        try:
                
            self.log.info("Starting processing new domain")
            self.log.info(domain)
            domain = re.sub(r'^https?://', '', domain)
            domain = domain.rstrip('/')
            if scantype == "single":
                url=self.add_https_if_missing(domain)
                collection = self.db["domains"]
                existing_document = collection.find_one({"Domain": domain})
                if existing_document is None:
                    new_document = {"Scanid":scanid,"Domain": domain,"Ports":[],"Technology":{},"Vulns":{},"Links":{},"ScanLinks":{},"Paths":[],"Paths403":[],"Screenshot":"","resolve":True,"active":True,"data":{},"status":{"processing":[],"finished":[],"failed":[]}}
                    collection.insert_one(new_document)
                    task = Task({"type": "subdomain",
                                        "stage": "new"})
                    task.add_payload("data", url)
                    task.add_payload("subdomain", domain)
                    task.add_payload("source", "subrecon")
                    self.send_task(task)
            else:
                result,active=self.scan(domain)
                db=self.db
                collection = db["domains"]

                for url in result:
                    try:
                        existing_document = collection.find_one({"Domain": url})
                        if existing_document is None:
                            new_document = {"Scanid":scanid,"Domain": url,"Ports":[],"Technology":{},"Vulns":{},"Links":{},"ScanLinks":{},"Paths":[],"Paths403":[],"Screenshot":"","resolve":True,"active":False,"data":{},"status":{"processing":[],"finished":[],"failed":[]}}
                            
                            if self.no_resolve_or_local_ip(url) == True:
                                new_document["resolve"] = False
                                
                            collection.insert_one(new_document)
                            task = Task({"type": "subdomain",
                                        "stage": "takeover"})
                            task.add_payload("domain", url)
                            task.add_payload("source", "subrecon")
                            self.send_task(task)

                    except Exception as e:
                        self.log.error("error happened ")
                        self.log.error(e)
                        # raise Exception(e)
                for url in active:
                    if url != "":
                        try:
                            domain = re.sub(r'^https?://', '', url)
                            domain = domain.rstrip('/')

                            existing_document = collection.find_one({"Domain": domain,"active":True})
                            if existing_document is None:

                                task = Task({"type": "subdomain",
                                            "stage": "new"})
                                task.add_payload("data", url)
                                task.add_payload("subdomain", url)
                                task.add_payload("source", "subrecon")
                                self.send_task(task)
                                domain = re.sub(r'^https?://', '', url)
                                domain = domain.rstrip('/')

                                collection.update_one({"Domain": domain}, {"$set": {"active": True}})
                        except Exception as e:
                            self.log.error(e)
                            # raise Exception(e)

                self.update_task_status(domain,"Finished")

        except Exception as e:
            self.update_task_status(domain,"Failed")
            
            self.log.error(e)
            # raise Exception("Error happened while processing")
            raise Exception(e)