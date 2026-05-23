PDS4: NASA Planetary Data System version 4 (PDS4) format

To create test files:
sudo apt install gdal-bin
gdal_translate "<VRTDataset rasterXSize='10' rasterYSize='10'><VRTRasterBand dataType='Byte'><ColorInterp>Gray</ColorInterp></VRTRasterBand></VRTDataset>" -of PDS4 test_pds4.xml

To test that it is valid:
gdalinfo test_pds4.xml

Notes:
  - gdalinfo: The XML parser is not XML compliant.
    They have a hard limit of 1024 bytes of header before the first tag.
    The SEAL signature with external file signatures pushes it past the limit.
    (With these test files, it becomes around 1044 bytes.)

  - The signed file should work with NASA's pds4-jparser.
    https://github.com/NASA-PDS/pds4-jparser

For maximum compatibility, use a SEAL sidecar.
For example, to sign all of the files and use the manifest as the main file:
  sealtool -S --ext=test_pds4* --sidecar test_pds4.seal test_pds4.xml
Validate using:
  sealtool --sidecar test_pds4.seal test_pds4.xml

