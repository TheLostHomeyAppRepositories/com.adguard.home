'use strict';

const Homey = require('homey');
const axios = require('axios');
const http = require('http');


module.exports = class AdGuardHomeDevice extends Homey.Device {

  /**
   * onInit is called when the device is initialized.
   */
  async onInit() {
    this._httpAgent = new http.Agent({
      keepAlive: true,
      keepAliveMsecs: 10000,
      maxSockets: 10,
      maxFreeSockets: 4,
      timeout: 15000,
    });
    if (!this.getStoreValue('baseUrl')) {
      this.setStoreValue('baseUrl', `http://${this.getStoreValue('ip')}`);
    }
    try {
      const baseUrl = this.getStoreValue('baseUrl');
      this._apiClient = axios.create({
        baseURL: baseUrl,
        httpAgent: this._httpAgent,
        timeout: 10000,
      });
    } catch (error) {
      this.error('Error initializing HTTP client:', error.message);
      this.setUnavailable();
      return;
    }
    const user = this.getStoreValue('user');
    const pass = this.getStoreValue('pass');
    this._basicAuth = Buffer.from(`${user}:${pass}`).toString('base64');
    this.log('AdGuard Home device has been initialized');
    this.registerCapabilityListener('protection', async (value) => {
      if (value === true) {
        await this.setProtection(true);
      } else {
        await this.setProtection(false);
      }
    });
    const conditionCard = this.homey.flow.getConditionCard('protection_condition');
    conditionCard.registerRunListener(async (args, state) => {
      return await this.getCapabilityValue('protection');
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
    const updateBlocklistsCard = this.homey.flow.getActionCard('update_blocklists');
    updateBlocklistsCard.registerRunListener(async (args, state) => {
      await this.updateLists(false);
      return true;
    });
    const updateWhitelistsCard = this.homey.flow.getActionCard('update_whitelists');
    updateWhitelistsCard.registerRunListener(async (args, state) => {
      await this.updateLists(true);
      return true;
    });
    this.pollingInterval = this.homey.setInterval(() => {
      this.pollAdguard();
    }, 5000);
    this.pollAdguard();
  }

  async setProtection(enable) {
    try {
      await this._apiClient.post(`/control/protection`, {
        enabled: enable,
        duration: null
      }, {
        headers: {
          'Authorization': `Basic ${this._basicAuth}`
        }
      });
      this.log(`Protection ${enable ? "enable" : "disable"}d successfully`);
    } catch (error) {
      this.error(`Error trying to ${enable ? "enable" : "disable"} protection:`, error.message);
      throw new Error(`Failed to ${enable ? "enable" : "disable"} protection`);
    }
  }

  async updateLists(whitelist) {
    try {
      await this._apiClient.post(`/control/filtering/refresh`, {
        whitelist
      }, {
        headers: {
          'Authorization': `Basic ${this._basicAuth}`
        }
      });
      this.log("Lists updated!");
    } catch (error) {
      this.error(`Error updating lists:`, error.message);
      throw new Error(`Failed to update lists`);
    }
  }

  async pollAdguard() {
    try {
      try {
        const response = await this._apiClient.get(`/control/status`, {
          headers: {
            'Authorization': `Basic ${this._basicAuth}`
          }
        });
        await this.setAvailable();
        const isEnabled = response.data.protection_enabled;
        if (this._firstRunCompleted === true) {
          if (this._oldProtectionStatus !== isEnabled) {
            if (isEnabled) {
              this.driver.triggerFlow('protection_enabled', this, {}, {});
            } else {
              this.driver.triggerFlow('protection_disabled', this, {}, {});
            }
          }
        }
        if (this._oldProtectionStatus !== undefined) {
          this._oldProtectionStatus = isEnabled;
        }
        await this.setCapabilityValue("protection", isEnabled);
        this._firstRunCompleted = true;
      } catch (error) {
        this.error('Error polling AdGuard Home:', error.message);
      }
      try {
        const response = await this._apiClient.get(`/control/stats`, {
          headers: {
            'Authorization': `Basic ${this._basicAuth}`
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
    } catch (error) {
      this.error('Error in pollAdguard:', error.message);
      await this.setUnavailable("Could not connect to AdGuard Home");
    }
  }

  /**
   * onAdded is called when the user adds the device, called just after pairing.
   */
  async onAdded() {
    this.log('AdGuard Home device has been added');
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
    this.log('AdGuard Home device settings where changed');
  }

  /**
   * onRenamed is called when the user updates the device's name.
   * This method can be used this to synchronise the name to the device.
   * @param {string} name The new name
   */
  async onRenamed(name) {
    this.log('AdGuard Home device was renamed');
  }

  /**
   * onDeleted is called when the user deleted the device.
   */
  async onDeleted() {
    this.log('AdGuard Home device has been deleted');
    this.homey.clearInterval(this.pollingInterval);
  }

};
