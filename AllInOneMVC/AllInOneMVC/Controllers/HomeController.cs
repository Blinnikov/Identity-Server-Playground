﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Web;
using System.Web.Mvc;

using Thinktecture.IdentityModel.Mvc;

namespace AllInOneMVC.Controllers {
    public class HomeController : Controller {
        public ActionResult Index() {
            return View();
        }

        [Authorize]
        public ActionResult About() {
            ViewBag.Message = "Your application description page.";
            return View((User as ClaimsPrincipal).Claims);
        }

        [ResourceAuthorize("Read", "ContactDetails")]
        public ActionResult Contact() {
            ViewBag.Message = "Your contact page.";

            return View();
        }

        [ResourceAuthorize("Write", "ContactDetails")]
        [HandleForbidden]
        public ActionResult UpdateContact() {
            ViewBag.Message = "Update your contact details!";

            return View();
        }

        public ActionResult Logout() {
            Request.GetOwinContext().Authentication.SignOut();
            return Redirect("/");
        }
    }
}