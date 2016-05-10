/*
 * (C) Copyright ${year} Nuxeo SA (http://nuxeo.com/) and contributors.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Contributors:
 *     vdutat
 */

package org.nuxeo.ecm.webengine.invite;

import java.io.Serializable;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.ecm.platform.web.common.vh.VirtualHostHelper;
import org.nuxeo.ecm.user.invite.AlreadyProcessedRegistrationException;
import org.nuxeo.ecm.user.invite.DefaultInvitationUserFactory;
import org.nuxeo.ecm.user.invite.UserInvitationService;
import org.nuxeo.ecm.user.invite.UserRegistrationException;
import org.nuxeo.ecm.webengine.forms.FormData;
import org.nuxeo.ecm.webengine.invite.UserInvitationObject;
import org.nuxeo.ecm.webengine.model.Template;
import org.nuxeo.ecm.webengine.model.WebObject;
import org.nuxeo.runtime.api.Framework;


/**
 * The root entry for the WebEngine module.
 *
 */
@Path("/customUserInvitation")
@Produces("text/html;charset=UTF-8")
@WebObject(type="customUserRegistration")
public class CustomUserInvitationObject extends UserInvitationObject {

    private static final Log log = LogFactory.getLog(CustomUserInvitationObject.class);

    @Override
    @POST
    @Path("validate")
    public Object validateTrialForm() {
        log.debug("<validateTrialForm> ");
        FormData formData = getContext().getForm();
        String requestId = formData.getString("RequestId");
        String configurationName = formData.getString("ConfigurationName");
        String password = formData.getString("Password");
        String passwordConfirmation = formData.getString("PasswordConfirmation");

        UserInvitationService usr = fetchService();
        // Check if the requestId is an existing one
        try {
            usr.checkRequestId(requestId);
        } catch (AlreadyProcessedRegistrationException ape) {
            return getBaseView("ValidationErrorTemplate").arg("exceptionMsg",
                    ctx.getMessage("label.error.requestAlreadyProcessed"));
        } catch (UserRegistrationException ue) {
            return getBaseView("ValidationErrorTemplate").arg("exceptionMsg",
                    ctx.getMessage("label.error.requestNotExisting", requestId));
        }

        // Check if both entered passwords are correct
        if (password == null || "".equals(password.trim())) {
            return redisplayFormWithErrorMessage("EnterPassword",
                    ctx.getMessage("label.registerForm.validation.password"), formData);
        }
        if (passwordConfirmation == null || "".equals(passwordConfirmation.trim())) {
            return redisplayFormWithErrorMessage("EnterPassword",
                    ctx.getMessage("label.registerForm.validation.passwordconfirmation"), formData);
        }
        password = password.trim();
        passwordConfirmation = passwordConfirmation.trim();
        if (!password.equals(passwordConfirmation)) {
            return redisplayFormWithErrorMessage("EnterPassword",
                    ctx.getMessage("label.registerForm.validation.passwordvalidation"), formData);
        }

        // Check password against user manager's password pattern
        UserManager um = Framework.getService(UserManager.class);
        if (!um.validatePassword(password)) {
            return redisplayFormWithErrorMessage("EnterPassword", ctx.getMessage("label.registerForm.validation.passwordpatternmismatch", Arrays.asList(um.getUserPasswordPattern().toString())), formData);
        }

        Map<String, Serializable> registrationData = new HashMap<String, Serializable>();
        try {
            Map<String, Serializable> additionalInfo = buildAdditionalInfos();

            // Add the entered password to the document model
            additionalInfo.put(DefaultInvitationUserFactory.PASSWORD_KEY, password);
            // Validate the creation of the user
            registrationData = usr.validateRegistration(requestId, additionalInfo);

        } catch (AlreadyProcessedRegistrationException ape) {
            log.info("Try to validate an already processed registration");
            return getBaseView("ValidationErrorTemplate").arg("exceptionMsg",
                    ctx.getMessage("label.error.requestAlreadyProcessed"));
        } catch (UserRegistrationException ue) {
            log.warn("Unable to validate registration request", ue);
            return getBaseView("ValidationErrorTemplate").arg("exceptionMsg",
                    ctx.getMessage("label.errror.requestNotAccepted"));
        }
        // User redirected to the logout page after validating the password
        HttpServletRequest request2 = getContext().getRequest();
        String webappName = VirtualHostHelper.getWebAppName(request2);
        String logoutUrl = "/" + webappName + "/logout";
        return getBaseView("UserCreated").arg("data", registrationData).arg("logout", logoutUrl);
    }

    @Override
    protected Template redisplayFormWithMessage(String messageType, String formName, String message, FormData data) {
        Map<String, String> savedData = new HashMap<String, String>();
        for (String key : data.getKeys()) {
            savedData.put(key, data.getString(key));
        }
        return getBaseView(formName).arg("data", savedData).arg(messageType, message);
    }

    /**
     * Retrieves view of original web object 'userRegistration'.
     *
     * @param viewName view name
     * @return template instance of requested view
     */
    protected Template getBaseView(String viewName) {
        return newObject("userRegistration").getView(viewName);
    }
}
