from google.oauth2 import service_account
from googleapiclient.discovery import build

PACKAGE_NAME = "kr.co.smartgauge"   
SCOPES = ["https://www.googleapis.com/auth/androidpublisher"]

def get_service():
    credentials = service_account.Credentials.from_service_account_file(
        "smartgauge-service-key.json", 
        scopes=SCOPES
    )
    service = build("androidpublisher", "v3", credentials=credentials)
    return service
