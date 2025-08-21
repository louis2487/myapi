import os, json
from google.oauth2 import service_account
from googleapiclient.discovery import build

PACKAGE_NAME = "kr.co.smartgauge"   
SCOPES = ["https://www.googleapis.com/auth/androidpublisher"]


def get_service():
    info = json.loads(os.environ["SERVICE_ACCOUNT_JSON"])
    credentials = service_account.Credentials.from_service_account_info(info, scopes=SCOPES)
    service = build("androidpublisher", "v3", credentials=credentials)
    return service
