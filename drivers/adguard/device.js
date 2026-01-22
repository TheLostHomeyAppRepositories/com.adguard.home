'use strict';

const Homey = require('homey');
const axios = require('axios');

module.exports = class AdGuardHomeDevice extends Homey.Device {

  /**
   * onInit is called when the device is initialized.
   */
  async onInit() {
    this.log('MyDevice has been initialized');
    this.registerCapabilityListener('protection', async (value) => {
      if (value === true) {
        await this.setProtection(true);
      } else {
        await this.setProtection(false);
      }
    });
    const enableCard = this.homey.flow.getActionCard('enable_protection');
    enableCard.registerRunListener(async (args, state) => {
      await this.setProtection(true);
      return true;
    });
    const disableCard = this.homey.flow.getActionCard('disable_protection');
    disableCard.registerRunListener(async (args, state) => {
      await this.setProtection(false);
      return true;
    });
    this.homey.setInterval(() => {
      this.pollAdguard();
    }, 4000);
    this.pollAdguard();
  }

  async setProtection(enable) {
    const ip = this.getStoreValue('ip');
    const user = this.getStoreValue('user');
    const pass = this.getStoreValue('pass');
    const basicAuth = Buffer.from(`${user}:${pass}`).toString('base64');
    
    try {
      await axios.post(`http://${ip}/control/protection`, {
        enabled: enable,
        duration: null
      }, {
        headers: {
          'Authorization': `Basic ${basicAuth}`
        }
      });
      this.log(`Protection ${enable}d successfully`);
    } catch (error) {
      this.error(`Error trying to ${enable} protection:`, error.message);
      throw new Error(`Failed to ${enable} protection`);
    }
  }

  async pollAdguard() {
    const ip = this.getStoreValue('ip');
    const user = this.getStoreValue('user');
    const pass = this.getStoreValue('pass');
    const basicAuth = Buffer.from(`${user}:${pass}`).toString(`base64`);
    try {
      const response = await axios.get(`http://${ip}/control/status`, {
        headers: {
          'Authorization': `Basic ${basicAuth}`
        }
      });
      const isEnabled = response.data.protection_enabled;
      this.log('Polled protection status:', isEnabled);
      if (this._firstRunCompleted === true) {
        if (this._oldProtectionStatus !== isEnabled) {
          if (isEnabled) {
            this.driver.triggerFlow('protection_enabled', this, {}, {});
          } else {
            this.driver.triggerFlow('protection_disabled', this, {}, {});
          }
        }
      }
      this._oldProtectionStatus = isEnabled;
      this.log('Setting protection capability to:', isEnabled);
      this.setCapabilityValue("protection", isEnabled);
      this._firstRunCompleted = true;
    } catch (error) {
      this.error('Error polling AdGuard Home:', error.message);
    }
    try {
      const response = await axios.get(`http://${ip}/control/stats`, {
        headers: {
          'Authorization': `Basic ${basicAuth}`
        }
      });
      const data = response.data;
      const allQueries = data.num_dns_queries;
      const blockedFilters = data.num_blocked_filtering;
      const blockedAdult = data.num_replaced_parental;
      const blockedSafeSearch = data.num_replaced_safesearch;
      const blockedMalware = data.num_replaced_safebrowsing;
      if (allQueries) {
        this.setCapabilityValue("total_queries",allQueries);
      }
      if (blockedFilters) {
        this.setCapabilityValue("blocked_filtering",blockedFilters);
      }
      if (blockedAdult) {
        this.setCapabilityValue("blocked_adult",blockedAdult);
      }
      if (blockedSafeSearch) {
        this.setCapabilityValue("blocked_safesearch",blockedSafeSearch);
      }
      if (blockedMalware) {
        this.setCapabilityValue("blocked_malware",blockedMalware);
      }
    } catch (error) {
      this.error('Error polling AdGuard Home stats:', error.message);
    }
  }

  /**
   * onAdded is called when the user adds the device, called just after pairing.
   */
  async onAdded() {
    this.log('MyDevice has been added');
  }

  /**
   * onSettings is called when the user updates the device's settings.
   * @param {object} event the onSettings event data
   * @param {object} event.oldSettings The old settings object
   * @param {object} event.newSettings The new settings object
   * @param {string[]} event.changedKeys An array of keys changed since the previous version
   * @returns {Promise<string|void>} return a custom message that will be displayed
   */
  async onSettings({ oldSettings, newSettings, changedKeys }) {
    this.log('MyDevice settings where changed');
  }

  /**
   * onRenamed is called when the user updates the device's name.
   * This method can be used this to synchronise the name to the device.
   * @param {string} name The new name
   */
  async onRenamed(name) {
    this.log('MyDevice was renamed');
  }

  /**
   * onDeleted is called when the user deleted the device.
   */
  async onDeleted() {
    this.log('MyDevice has been deleted');
  }

};
