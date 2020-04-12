import { Component, OnInit } from '@angular/core';
import { Router } from '@angular/router';
import { CVSS_export } from '../../assets/js/cvsscalc30.js';

@Component({
  selector: 'app-calc',
  templateUrl: './calc.component.html',
  styleUrls: ['./calc.component.css']
})
export class CalcComponent implements OnInit {

  constructor(private router: Router, private window: Window) { }

  ngOnInit() {
    this.loadScript('../../assets/js/cvsscalc30.js');
    this.loadScript('../../assets/js/cvsscalculator.js');
    this.loadScript('../../assets/js/cvsscalc30_helptext.js');

    window['CVSS_export'] = CVSS_export;
  }

  public loadScript(url: string) {
    const body = <HTMLDivElement> document.body;
    const script = document.createElement('script');
    script.innerHTML = '';
    script.src = url;
    script.async = true;
    script.defer = false;
    if(url === '../../assets/js/cvsscalc30.js') {
      script.type = "module";
    }
    body.appendChild(script);
  }
}
