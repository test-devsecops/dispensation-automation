class CxApiEndpoints:

    @staticmethod
    def openid_token(tenant_name):
        endpoint = f"/auth/realms/{tenant_name}/protocol/openid-connect/token"
        return endpoint
    
    @staticmethod
    def retrieve_projects():
        endpoint = "/api/projects/"
        return endpoint

    @staticmethod
    def sca_update_package_state():
        endpoint = "/api/sca/management-of-risk/packages/bulk"
        return endpoint
    
    @staticmethod
    def sca_vuln_details_graphql():
        endpoint = f"/api/sca/graphql/graphql"
        return endpoint
