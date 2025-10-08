import requests

class HttpRequests:
    def __init__(self, logger=None):
        self.logger = logger
    
    def _handle_response(self, response, valid_status_codes, method_name):
        if self.logger:
            self.logger.info(f"{method_name} {response.url} - Status Code: {response.status_code}")

        # Successful response
        if response.status_code in valid_status_codes:
            if response.content and response.content.strip():
                try:
                    return response.json()
                except ValueError:
                    return response.text
            else:
                return None
        else:
            # Error response
            try:
                error_details = response.json()
            except ValueError:
                error_details = response.text

            # Log the error for visibility
            if self.logger:
                self.logger.error(
                    f"{response.status_code} Error: {response.reason} for url: {response.url} | Response: {error_details}"
                )

            # Return both status and error details
            return error_details

    def post_api_request(self, url, headers=None, data=None, params=None, json=None):
        response = requests.post(url, headers=headers, data=data, params=params, json=json, timeout=120)
        return self._handle_response(response, [200, 201], "POST")

    def get_api_request(self, url, headers=None, data=None, params=None, json=None):
        response = requests.get(url, headers=headers, data=data, params=params, json=json)
        return self._handle_response(response, [200, 201], "GET")

    def patch_api_request(self, url, headers=None, data=None, params=None, json=None):
        response = requests.patch(url, headers=headers, data=data, params=params, json=json)
        return self._handle_response(response, [200, 201], "PATCH")

    def delete_api_request(self, url, headers=None, data=None, params=None, json=None):
        response = requests.delete(url, headers=headers, data=data, params=params, json=json, timeout=360)
        return self._handle_response(response, [200, 204], "DELETE")
    
    def put_api_request(self, url, headers=None, data=None, params=None, json=None):
        response = requests.put(url, headers=headers, data=data, params=params, json=json, timeout=120)
        return self._handle_response(response, [200, 204], "PUT")
