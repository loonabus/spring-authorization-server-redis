package io.doe.web;

import io.doe.domain.BaseRes;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.autoconfigure.web.servlet.error.AbstractErrorController;
import org.springframework.boot.web.servlet.error.ErrorAttributes;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.List;

/**
 * @author <loonabus@gmail.com>
 * @version 1.0.0
 * @see ErrorController
 * @since 2024-07-08
 */

@Controller
@RequestMapping("${server.error.path:${error.path:/error}}")
public class ErrorController extends AbstractErrorController {

	public ErrorController(final ErrorAttributes attributes) { super(attributes, List.of()); }

	@RequestMapping
	public ResponseEntity<BaseRes<Void>> sendError(final HttpServletRequest request) {

		final HttpStatus status = getStatus(request);

		if (status == HttpStatus.NO_CONTENT) {
			return new ResponseEntity<>(BaseRes.from(""), HttpStatus.NO_CONTENT);
		}

		return new ResponseEntity<>(BaseRes.from("some un-pre-processed error"), HttpStatus.valueOf(status.value()));
	}
}
