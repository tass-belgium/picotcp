module Net
  module DNS
    module Version

      MAJOR = 0
      MINOR = 8
      PATCH = 0
      BUILD = nil

      STRING = [MAJOR, MINOR, PATCH, BUILD].compact.join(".")
    end

    VERSION = Version::STRING

  end
end