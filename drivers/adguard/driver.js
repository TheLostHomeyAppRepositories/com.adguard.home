'use strict';

const Homey = require('homey');
const axios = require('axios');

module.exports = class AdGuardHomeDriver extends Homey.Driver {

  /**
   * onInit is called when the driver is initialized.
   */
  async onInit() {
    this.log('MyDriver has been initialized');
  }

  triggerFlow(card, device, tokens, state) {
    const flowcard = this.homey.flow.getDeviceTriggerCard(card);
    flowcard.trigger(device, tokens, state);
  }

  async onPair(session) {
    session.setHandler("ip", async (data) => {
      try {
        this.log('Checking IP address:', data.ip);
        const response = await axios.get(`http://${data.ip}/assets/favicon.png`);
        this.log(response.headers['content-length'])
        if (Number(response.headers['content-length']) === 1296) {
          this._ip = data.ip;
          await session.showView('login');
          return true;
        } else {
          return false;
        }
      } catch (error) {
        this.error('Error during IP check:', error.message);
        return false;
      }
    });

    session.setHandler("login", async (data) => {
      try {
        const ip = this._ip;
        this.log('Attempting login for user:', data.user);
        this.log('Using IP address:', ip);
        this.log('With password:', data.pass);
        const basicAuth = Buffer.from(`${data.user}:${data.pass}`).toString('base64');
        this.log('Using Basic Auth:', basicAuth);
        const response = await axios.get(`http://${ip}/control/stats`, {
          headers: {
            'Authorization': `Basic ${basicAuth}`
          }
        });
        return { ip: ip, user: data.user, pass: data.pass };
      } catch (error) {
        if (error.response?.status === 401) {
          this.error('Authentication failed:', error.message);
          return false;
        }
        throw new Error('Connection error');
      }
    });
  }

  /**
   * onPairListDevices is called when a user is adding a device
   * and the 'list_devices' view is called.
   * This should return an array with the data of devices that are available for pairing.
   */
  async onPairListDevices() {
    return [
      // Example device data, note that `store` is optional
      // {
      //   name: 'My Device',
      //   data: {
      //     id: 'my-device',
      //   },
      //   store: {
      //     address: '127.0.0.1',
      //   },
      // },
    ];
  }

};
