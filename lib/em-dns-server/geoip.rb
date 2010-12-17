begin
  require 'geoip'
rescue LoadError
  puts "-- geoip gem not installed, geoip support disabled."
end

module DNSServer

  module GeoIPRoute

    RAD_PER_DEG = 0.017453293

    def self.included(base) 
      class << base
        @@GEOIP = nil

        def geoip_data_path
          @@GEOIP_PATH ||= File.expand_path(File.join(DNSServer::PLUGIN_PATH,"GeoLiteCity.dat"))
        end

        def geoip_data_path=(val)
          @@GEOIP_PATH = val
        end

        def geoip_enabled?
          !@@GEOIP.nil?
        end
      end
    end

    def haversine_distance( lat1, lon1, lat2, lon2 )
      distances = Hash.new
      dlon = lon2 - lon1
      dlat = lat2 - lat1
  
      dlon_rad = dlon * RAD_PER_DEG
      dlat_rad = dlat * RAD_PER_DEG

      lat1_rad = lat1 * RAD_PER_DEG
      lon1_rad = lon1 * RAD_PER_DEG

      lat2_rad = lat2 * RAD_PER_DEG
      lon2_rad = lon2 * RAD_PER_DEG

      a = Math.sin(dlat_rad/2)**2 + Math.cos(lat1_rad) * Math.cos(lat2_rad) * Math.sin(dlon_rad/2)**2
      c = 2 * Math.asin( Math.sqrt(a))

      dMi = 3956 * c          # delta between the two points in miles
      dKm = 6371 * c             # delta in kilometers
      dFeet = 20887680 * c         # delta in feet
      dMeters = 6371000 * c     # delta in meters

      distances["mi"] = dMi
      distances["km"] = dKm
      distances["ft"] = dFeet
      distances["m"] = dMeters
      distances
    end

  end

end
