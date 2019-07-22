package fi.metatavu.feign;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import feign.Feign.Builder;
import feign.Response;
import feign.RetryableException;
import feign.codec.ErrorDecoder.Default;

/**
 * Feign error decoder that handles UMA token switching
 * 
 * @author Antti Leppä
 */
public class UmaErrorDecoder extends Default {
  
  private Builder feignBuilder;
  private String authorization;
  private Consumer<String> authorizationChange;
  
  /**
   * Constructor
   * 
   * @param authorization original authorization string
   * @param authorizationChange method that is run when authorization changes
   */
  public UmaErrorDecoder(Builder feignBuilder, String authorization, Consumer<String> authorizationChange) {
    super();
    this.feignBuilder = feignBuilder;
    this.authorization = authorization;
    this.authorizationChange = authorizationChange;
  }

  @Override
  public Exception decode(String methodKey, Response response) {
    if (response.status() == 401) {      
      Map<String, String> umaTicket = getUmaTicket(response);
      if (umaTicket != null) {
        try {
          String rpt = getRPT(authorization, umaTicket);
          if (rpt != null) {
            authorizationChange.accept(String.format("Bearer %s", rpt));
            return new RetryableException("UMA", null);
          } else {
            return new RptForbiddenFeignException("No RPT Token");
          }
          
        } catch (UnsupportedOperationException | IOException e) {
          return e;
        }
      } else {
        return new RptForbiddenFeignException("No UMA Ticket");
      }
    }
    return super.decode(methodKey, response);
  }
  
  /**
   * Returns UMA ticket from www-authenticate header or null if not found
   * 
   * @param response response
   * @returns {Object} UMA ticket components
   */
  private Map<String, String> getUmaTicket(Response response) {
    Collection<String> headerValues = response.headers().get("www-authenticate");
    if (headerValues != null && !headerValues.isEmpty()) {
      String authenticate = headerValues.iterator().next();
      
      if (authenticate != null && authenticate.startsWith("UMA ")) {
        return Arrays.stream(authenticate.substring(4).split(","))
          .collect(Collectors.toMap((component) -> {
            int equalsIndex = component.indexOf('=');
            return component.substring(0, equalsIndex);
          }, (component) -> {
            int equalsIndex = component.indexOf('=');
            return component.substring(equalsIndex + 2, component.length() - 1);
          }));
      }
    }
    
    return null;
  }
  
  /**
   * Retrieves RPT token
   * 
   * @param authorization authorization
   * @param ticket UMA ticket
   * @return token token or null if token creation has fails
   * @throws IOException when io error fails
   */
  private String getRPT(String authorization, Map<String, String> ticket) throws IOException {
    if (authorization == null || "".equals(authorization.trim())) {
      return null;
    }
    
    String url = ticket.get("as_uri");
    if (url == null) {
      throw new RptForbiddenFeignException("UMA ticket does not contain as_uri");
    }
    
    TokenEndpoint tokenEndpoint = feignBuilder.target(TokenEndpoint.class, url);
    AccessToken accessToken = tokenEndpoint.getAccessToken(authorization, ticket.get("ticket"));
    if (accessToken == null || accessToken.getAccessToken() == null) {
      throw new RptForbiddenFeignException("Failed to retrieve access token");
    }
    
    return accessToken.getAccessToken();
    
  }
  
}
