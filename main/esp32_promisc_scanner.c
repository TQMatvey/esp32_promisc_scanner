#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_wifi_types.h"

static const uint8_t friend_mac[6] = {0xD4, 0x3A, 0x2C, 0x51, 0x5F, 0x33}; // My Pixel 8 WLAN-MAC

void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT)
        return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buff;
    const uint8_t *frame_buf = pkt->payload;

    // The first 24 bytes are the IEEE 802.11 MAC header
    if (pkt->rx_ctrl.sig_mode == 0)
    {                                          // Check if it's not HT (802.11n)
        const uint8_t *addr2 = frame_buf + 10; // Source address is at 10th byte

        if (memcmp(addr2, friend_mac, 6) == 0)
        {
            printf("Friend detected with MAC: %02x:%02x:%02x:%02x:%02x:%02x, on Channel %d\n",
                   addr2[0], addr2[1], addr2[2], addr2[3], addr2[4], addr2[5], pkt->rx_ctrl.channel);
        }
    }
}

void app_main(void)
{
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Init and start WiFi in promiscuous mode
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_packet_handler));
}
