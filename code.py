import json
import requests
import datetime
import hashlib
import hmac
import base64
import datetime

workspace_id = 'a1fe7441-13ff-4972-9786-57569e1e133a'
shared_key = dbutils.secrets.get('msft-keys', 'la-shared-key')
log_type = 'MyDatabricksApplication'

log_props_config = {
  'app_name': 'spark.app.name',
  'app_id': 'spark.app.id',
  'cluster_id': 'spark.databricks.clusterUsageTags.clusterId',
  'cluster_name': 'spark.databricks.clusterUsageTags.clusterName',
  'driver': 'spark.driver.host',
  'master': 'spark.master',
  'worker': 'spark.databricks.clusterUsageTags.workerEnvironmentId',
  'cluster_source': 'spark.databricks.clusterSource',
  'spark_version': 'spark.databricks.clusterUsageTags.sparkVersion',
  'driver_dns': 'spark.databricks.clusterUsageTags.driverPublicDns'
}

#####################
######Functions######  
#####################

def build_log_message():
  log_props = {}
  for key in log_props_config:
    log_props[key] = spark.conf.get(log_props_config[key])
  return log_props

# Build the API signature
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, 'utf-8')
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest())
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash.decode('utf-8'))
    return authorization

# Build and send a request to the POST API
def post_data(customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        print('Accepted')
    else:
        print("Response code: {}".format(response.status_code))
        


def log_message(log_level, message):
  messages = [build_log_message()]
  messages[0]['log_level'] = log_level
  messages[0]['description'] = message
  messages[0]['app_log_time'] = datetime.datetime.now().strftime("%d-%b-%Y (%H:%M:%S.%f)")
  
  post_data(workspace_id, shared_key, json.dumps(messages), log_type)


  #log start
log_message('INFO', 'Application started')

#log start
log_message('INFO', 'Application finished')