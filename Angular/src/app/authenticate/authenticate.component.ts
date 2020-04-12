import { Component, OnInit } from "@angular/core";
import { FormBuilder, FormGroup, Validators } from "@angular/forms";
import { AuthenticateService } from "../services/authenticate.service";

@Component({
  selector: "app-authenticate",
  templateUrl: "./authenticate.component.html",
  providers: [AuthenticateService]
})
export class AuthenticateComponent implements OnInit {
  public error: string[] = [];
  public expired = false;
  loginForm: FormGroup;

  private firstUrl:string;
  private urlRegex = /^\/calc\#CVSS:3.0\/((AV:[NALP]|AC:[LH]|PR:[UNMLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLMH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])\/)*(AV:[NALP]|AC:[LH]|PR:[UNLH]|UI:[NR]|S:[UC]|[CIA]:[NLH]|E:[XUPFH]|RL:[XOTWU]|RC:[XURC]|[CIA]R:[XLMH]|MAV:[XNALP]|MAC:[XLH]|MPR:[XUNLH]|MUI:[XNR]|MS:[XUC]|M[CIA]:[XNLH])$/
  private cleanUrl:string;

  get formControls() {
    return this.loginForm.controls;
  }

  constructor(
    public _authenticateService: AuthenticateService,
    private formBuilder: FormBuilder
  ) {}

  ngOnInit() {
    if (localStorage.getItem("session") == "expired") {
      this.expired = true;
    }
    localStorage.clear();
    this.loginForm = this.formBuilder.group({
      username: ["", Validators.required],
      password: ["", Validators.required]
    });

    this.firstUrl = sessionStorage.getItem("first_url");
    this.cleanUrl = this.firstUrl.substring(this.firstUrl.indexOf("/calc"));
  }

  onLogin() {
    this.error = [];
    this._authenticateService.authenticate(this.loginForm.value).subscribe(
      response => {
        if (response["Authorization token"]) {
          sessionStorage.setItem("auth_token", response["Authorization token"]);
          sessionStorage.setItem("user", response["username"]);

          location.replace(this.urlRegex.test(this.cleanUrl) ? sessionStorage.getItem("first_url") : "dashboard");
        }
      },
      () => this.error.push("Wrong username/password combination!")
    );
  }

  skipLogin() {
    sessionStorage.setItem("skip_login", "true");
    location.replace(this.urlRegex.test(this.cleanUrl) ? sessionStorage.getItem("first_url") : "dashboard");
  }
}
