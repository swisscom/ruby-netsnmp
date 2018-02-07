# frozen_string_literal: true

module NETSNMP
  class Timetick < Numeric
    # @param [Integer] ticks number of microseconds since the time it was read
    def initialize(ticks)
      @ticks = ticks
    end

    def to_s
      days = days_since
      hours = hours_since(days)
      minutes = minutes_since(hours)
      milliseconds = milliseconds_since(minutes)
      "Timeticks: (#{@ticks}) #{days.to_i} days, #{hours.to_i}:#{minutes.to_i}:#{milliseconds.to_f.round(2)}"
    end

    def to_i
      @ticks
    end

    def to_asn
      OpenSSL::ASN1::ASN1Data.new([@ticks].pack("N"), 3, :APPLICATION)
    end

    def coerce(other)
      [Timetick.new(other), self]
    end

    def <=>(other)
      to_i <=> other.to_i
    end

    def +(other)
      Timetick.new((to_i + other.to_i))
    end

    def -(other)
      Timetick.new((to_i - other.to_i))
    end

    def *(other)
      Timetick.new((to_i * other.to_i))
    end

    def /(other)
      Timetick.new((to_i / other.to_i))
    end

    private

    def days_since
      Rational(@ticks, 8_640_000)
    end

    def hours_since(days)
      Rational((days.to_f - days.to_i) * 24)
    end

    def minutes_since(hours)
      Rational((hours.to_f - hours.to_i) * 60)
    end

    def milliseconds_since(minutes)
      Rational((minutes.to_f - minutes.to_i) * 60)
    end
  end
end
