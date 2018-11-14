package fi.metatavu.feign;

import feign.Body;
import feign.Headers;
import feign.Param;
import feign.RequestLine;

public interface TokenEndpoint {

  @RequestLine("POST /protocol/openid-connect/token")
  @Headers({
    "Authorization: {authorization}",
    "Content-Type: application/x-www-form-urlencoded"
  })
  @Body("submit_request=false&grant_type=urn:ietf:params:oauth:grant-type:uma-ticket&ticket={ticket}")  
  AccessToken getAccessToken(@Param("authorization") String authorization, @Param("ticket") String ticket);
}