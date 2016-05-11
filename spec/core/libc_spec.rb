RSpec.describe NETSNMP::Core::C do
  it "exposes the free function" do
    expect(described_class).to respond_to(:free)
  end 
  it "wrapes the fdset struc as FDSet" do
    fdset = NETSNMP::Core::C::FDSet.new
    if FFI::Platform::IS_WINDOWS
      expect(fdset[:fd_count]).to be_zero
      expect(fdset[:fd_array]).not_to be_nil
      expect(fdset[:fd_array].size).to be(2048)
    else
      expect(fdset[:fds_bits]).not_to be_nil
      expect(fdset[:fds_bits].size).to be(128)

    end
  end
end
