from b_hunters.bhunter import BHunters
from karton.core import Task
from .__version__ import __version__
import os
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
    def findusbcommand(self,domain,rate=None,concurrency=None):
        result=[]
        active=[]
        try:
            folder1=self.generate_random_filename()
            # The scan's rate and concurrency travel with the task, and
            # the tool that asks the target about every host it found
            # answers at that rate.  A tool with its own default rate
            # is how a scan of a rate-limited edge becomes a block.
            environment=dict(os.environ)
            environment["RATE"]=str(rate if rate else 5)
            environment["CONCURRENCY"]=str(concurrency if concurrency else 3)
            output=subprocess.run(["/app/findsubs.sh",folder1,domain], capture_output=True, text=True, env=environment)
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

    def scan(self,url,rate=None,concurrency=None):
        result,active=self.findusbcommand(url,rate,concurrency)
        if result !=[]:
            return result,active
        return [],[]

    def host_of(self,url):
        """The host of a URL, or of a bare host name."""
        text = re.sub(r'^https?://', '', str(url or ""))
        text = text.rstrip('/')
        return text.split('/', 1)[0].split(':', 1)[0].lower()

    def dispatch_discovered(self,result,active,scanid):
        """Hand every host the discovery found to the rest of the fleet.

        ``result`` is what the discovery tools named and ``active`` is
        what answered, so the second is the one that is alive.  A host
        the scan excludes is not handed on at all: the discovery tools
        find whatever is out there, and the scope is what decides what
        may be tested.

        Every host gets a report of its own, because that is where the
        workers write what they find.
        """
        collection = self.db["domains"]
        collection2 = self.db["reports"]
        for url in result:
            try:
                host=self.host_of(url)
                if not host or self.is_denied_host(host):
                    continue
                existing_document = collection.find_one({"Domain": host,"Scanid":scanid})
                if existing_document is None:
                    new_document = {"Scanid":scanid,"Domain": host,"report_id":"","resolve":True,"active":False,"status":{"processing":[],"finished":[],"failed":[]}}
                    reports_document = {"Domain": host,"Ports":[],"Technology":{},"Vulns":{},"Paths":[],"Paths403":[],"Screenshot":"","data":{}}
                    if self.no_resolve_or_local_ip(host) == True:
                        new_document["resolve"] = False
                    collection.insert_one(new_document)
                    # The host is recorded and *not* handed on.  The
                    # legacy code published a "takeover" task for it,
                    # and no worker in the fleet binds to that stage:
                    # the task went to nobody, and a scan of a domain
                    # with a thousand subdomains published a thousand
                    # of them.  A host that does not answer is
                    # recorded here, and a host that does is scanned.
            except Exception as e:
                self.log.error("error happened ")
                self.log.error(e)
        for url in active:
            if url == "":
                continue
            try:
                host=self.host_of(url)
                if not host or self.is_denied_host(host):
                    continue
                reports_document = {"Domain": host,"Ports":[],"Technology":{},"Vulns":{},"Paths":[],"Paths403":[],"Screenshot":"","data":{}}
                existing_document = collection.find_one({"Domain": host,"Scanid":scanid,"active":True})
                if existing_document is None:
                    reports_document_result = collection2.insert_one(reports_document)
                    report_id = reports_document_result.inserted_id
                    task = Task({"type": "subdomain",
                                            "stage": "new"})
                    task.add_payload("data", url)
                    task.add_payload("subdomain", host)
                    task.add_payload("source", "subrecon")
                    task.add_payload("report_id", str(report_id),persistent=True)
                    self.send_task(task)
                    collection.update_one({"Domain": host,"Scanid":scanid}, {"$set": {"active": True,"report_id":ObjectId(report_id)}})
            except Exception as e:
                self.log.error(e)
                # raise Exception(e)
        
    def process(self, task: Task) -> None:
        domain = task.payload_persistent["domain"]
        scanid = task.payload_persistent["scan_id"]
        scantype = task.payload_persistent["scantype"]
        # The rate the scan allows against the target.  The discovery
        # asks the target about every host it found, so it answers at
        # the scan's rate.
        persistent = task.payload_persistent or {}
        rate = persistent.get("max_requests_per_second") or 5
        concurrency = persistent.get("max_concurrency") or 3
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
                # The discovery the single path never did.  The platform
                # asks for a domain, and the whole fleet works from what
                # is found: without this the scan only ever sees the
                # host that was named, and the discovery tools that sit
                # in this image are never run at all.
                self.log.info("looking for the hosts of %s", domain)
                result,active=self.scan(domain,rate,concurrency)
                self.log.info("the discovery found %d host(s), %d of them answering", len(result or []), len(active or []))
                self.dispatch_discovered(result,active,scanid)
            else:
                result,active=self.scan(domain,rate,concurrency)
                self.waitformongo()
                db=self.db
                self.dispatch_discovered(result,active,scanid)

                self.update_task_status(domain,"Finished")

        except Exception as e:
            self.update_task_status(domain,"Failed")
            
            self.log.error(e)
            # raise Exception("Error happened while processing")
            raise Exception(e)