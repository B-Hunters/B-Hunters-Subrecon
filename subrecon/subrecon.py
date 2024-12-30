from b_hunters.bhunter import BHunters
from karton.core import Task
from .__version__ import __version__
import subprocess
import shutil
import re
from bson.objectid import ObjectId



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
        scanid = task.payload_persistent["scan_id"]
        scantype = task.payload_persistent["scantype"]
        self.update_task_status(domain,"Started")

        try:
                
            self.log.info("Starting processing new domain")
            self.log.info(domain)
            domain = re.sub(r'^https?://', '', domain)
            domain = domain.rstrip('/')
            if scantype == "single":
                url=self.add_https_if_missing(domain)
                self.waitformongo()
                collection = self.db["domains"]
                collection2 = self.db["reports"]
                existing_document = collection.find_one({"Domain": domain,"Scanid":scanid})
                if existing_document is None:
                    reports_document = {"Domain": domain,"Ports":[],"Technology":{},"Vulns":{},"Paths":[],"Paths403":[],"Screenshot":"","data":{}}
                    reports_document_result = collection2.insert_one(reports_document)
                    report_id = reports_document_result.inserted_id

                    new_document = {"Scanid":scanid,"Domain": domain,"report_id":ObjectId(report_id),"resolve":True,"active":True,"status":{"processing":[],"finished":[],"failed":[]}}
                    collection.insert_one(new_document)
                    task = Task({"type": "subdomain",
                                        "stage": "new"})
                    task.add_payload("data", url)
                    task.add_payload("subdomain", domain)
                    task.add_payload("report_id", str(report_id),persistent=True)
                    task.add_payload("source", "subrecon")
                    self.send_task(task)
            else:
                result,active=self.scan(domain)
                self.waitformongo()
                db=self.db
                collection = self.db["domains"]
                collection2 = self.db["reports"]
                for url in result:
                    try:
                        existing_document = collection.find_one({"Domain": url,"Scanid":scanid})
                        if existing_document is None:
                            new_document = {"Scanid":scanid,"Domain": url,"report_id":"","resolve":True,"active":False,"status":{"processing":[],"finished":[],"failed":[]}}
                            reports_document = {"Domain": url,"Ports":[],"Technology":{},"Vulns":{},"Paths":[],"Paths403":[],"Screenshot":"","data":{}}
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
                            reports_document = {"Domain": domain,"Ports":[],"Technology":{},"Vulns":{},"Paths":[],"Paths403":[],"Screenshot":"","data":{}}

                            existing_document = collection.find_one({"Domain": domain,"Scanid":scanid,"active":True})
                            if existing_document is None:
                                reports_document_result = collection2.insert_one(reports_document)
                                report_id = reports_document_result.inserted_id
                                task = Task({"type": "subdomain",
                                            "stage": "new"})
                                task.add_payload("data", url)
                                task.add_payload("subdomain", url)
                                task.add_payload("source", "subrecon")
                                task.add_payload("report_id", str(report_id),persistent=True)
                                self.send_task(task)
                                domain = re.sub(r'^https?://', '', url)
                                domain = domain.rstrip('/')
                                collection.update_one({"Domain": domain,"Scanid":scanid}, {"$set": {"active": True,"report_id":ObjectId(report_id)}})

                        except Exception as e:
                            self.log.error(e)
                            # raise Exception(e)

                self.update_task_status(domain,"Finished")

        except Exception as e:
            self.update_task_status(domain,"Failed")
            
            self.log.error(e)
            # raise Exception("Error happened while processing")
            raise Exception(e)