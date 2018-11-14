package fi.metatavu.feign;

import feign.FeignException;

/**
 * Exception that indicates that Feign request has failed permanently with RPT ticket
 * 
 * @author Antti Leppä
 */
public class RptForbiddenFeignException extends FeignException {

  private static final long serialVersionUID = 7446622743057088666L;

  /**
   * Constructor
   * 
   * @param message message
   */
  protected RptForbiddenFeignException(String message) {
    super(403, message);
  }

}
