from b_hunters.bhunter import BHunters
from karton.core import Task
from .__version__ import __version__
import subprocess
import shutil
import re



class subrecon(BHunters):
    """
    Subrecon developed by Bormaa
    """

    identity = "B-Hunters-domain-starter"
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
        self.update_task_status(domain,"Started")

        try:
                
            self.log.info("Starting processing new domain")
            self.log.info(domain)
            domain = re.sub(r'^https?://', '', domain)
            domain = domain.rstrip('/')
            result,active=self.scan(domain)
            db=self.db
            collection = db["domains"]

            for url in result:
                try:
                    existing_document = collection.find_one({"Domain": url})
                    if existing_document is None:
                        new_document = {"Scanid":scanid,"Domain": url,"Ports":[],"Technology":[],"Vulns":[],"Links":[],"Paths":[],"Paths403":[],"Screenshot":"","resolve":True}
                        collection.insert_one(new_document)

                        if self.no_resolve_or_local_ip(url) == True:
                            new_document["resolve"] = False
                            
                        task = Task({"type": "subdomain",
                                    "stage": "takeover"})
                        task.add_payload("domain", url)
                        task.add_payload("source", "subrecon")
                        self.send_task(task)

                except Exception as e:
                    self.log.error(e)
            for url in active:
                if url != "":
                    try:
                        task = Task({"type": "subdomain",
                                    "stage": "new"})
                        task.add_payload("data", url)
                        task.add_payload("source", "subrecon")
                        self.send_task(task)
                    except Exception as e:
                        self.log.error(e)

            self.update_task_status(domain,"Finished")

        except Exception as e:
            self.update_task_status(domain,"Failed")

            self.log.error(e)
            raise Exception("Error happened while processing")